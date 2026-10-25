"""The publisher for an accepted tenant: a layout over the one publish root (#1279 A4).

A published view lands in the tenant's own area under the publish root, so no tenant's page can
overwrite or sit beside another's:
  - the page of run R → `<root>/<T>/runs/<R>/runtime.html`
  - a learning page → `<root>/<T>/learning/<name>`

Callers pass the `Tenant` they already accepted. The mirror and the learning build both publish
through here, so neither resolves a destination or writes on its own; blob serving becomes
another backend and the callers do not change.
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from defender.configuration import publish_root
from defender.presentation import _mirror_write
from defender.run_repository import RunId

if TYPE_CHECKING:
    from defender.tenancy._tenant import Tenant

#: The published run page's file name: the publish area's own, not a path into a run.
RUN_PAGE_NAME = "runtime.html"  # lint-run-records: ok — the published copy's own name in the publish area, not a record in a run

_MIRROR_WRITER = Path(_mirror_write.__file__).resolve()


class NoPublishRoot(Exception):
    """There is nowhere to publish (#1279 A9): `no_root` says why — not a `dev` deployment, or
    a `dev` root that cannot be determined."""

    def __init__(self, no_root: publish_root.NoRoot) -> None:
        super().__init__(f"nothing to publish into: {no_root.reason}")
        self.no_root = no_root


@dataclass(frozen=True)
class Target:
    """One publishable page: where it lands, and how it is written."""

    path: Path
    root: Path

    def write(self, text: str) -> None:
        _write(text.encode("utf-8"), self.path, self.root)


@dataclass(frozen=True)
class Publisher:
    root: Path
    tenant_id: str

    @classmethod
    def for_tenant(cls, tenant: Tenant) -> Publisher:
        """The publisher for `tenant`; `NoPublishRoot` when there is nowhere to publish: outside
        `dev` (O4), or in `dev` when the root cannot be determined (A9)."""
        root = publish_root.publish_root()
        if isinstance(root, publish_root.NoRoot):
            raise NoPublishRoot(root)
        return cls(root, str(tenant.id))

    def run_page(self, run_id: str) -> Target:
        """The page of run `run_id`, which must be a run id (`RunRefused` otherwise), so a
        path-like name never leaves the tenant's runs area."""
        run = str(RunId.parse(run_id))
        return Target(self.root / self.tenant_id / "runs" / run / RUN_PAGE_NAME, self.root)

    def learning_page(self, name: str) -> Target:
        if Path(name).name != name or name in ("", ".", ".."):
            raise ValueError(f"a learning page is a bare file name, not {name!r}")
        return Target(self.root / self.tenant_id / "learning" / name, self.root)


def _write(page: bytes, dest: Path, root: Path) -> None:
    """Write the page as the owner of the folder holding the publish root.

    Only root writing into a user's folder drops privileges: the copy then runs as that user,
    so a link they planted cannot take it anywhere they could not write. Otherwise it writes
    in-process."""
    try:
        owner = os.lstat(root.parent)
    except FileNotFoundError:
        owner = None
    if os.geteuid() != 0 or owner is None or owner.st_uid == 0:
        _mirror_write.write_page(dest, page)
        return
    proc = subprocess.run(  # noqa: S603 — fixed argv: this interpreter, the writer module
        [sys.executable, "-I", str(_MIRROR_WRITER), str(dest)],
        input=page, capture_output=True, cwd="/", check=False,
        user=owner.st_uid, group=owner.st_gid, extra_groups=[],
    )
    if proc.returncode != 0:
        raise OSError(
            f"publish write as uid {owner.st_uid} failed (exit {proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace').strip()}")
