"""#1618 (flow 5): the host actor's prepare reads the tenant's knowledge through the fetch child, not a clone.

FORCED: the seam name `HostActor(..., fetch=)` replaces `publish=` (the design names no seam: "call the child into a temporary and
discard it"). The seam is called `fetch(tenant_id, dest, *, data_root, **_)` with `dest` an empty folder the actor made, and answers
the child's one report line: `ok <commit>` or `refused <transient|lasting> <reason>` (as `knowledge_1618._support.Report`). The
FORCED `commit=` keyword is passed only for a pinned read: prepare passes none (main).
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from defender.tests.tenancy.lifecycle_1214._fakes import ORG
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld
from defender.lifecycle import HostActor


class RecordingFetch:
    """Records each call (tenant, destination, the destination's state at the call, any commit named) and answers one report line:
    the queued `answers` first, else `ok <tip of the tenant's bare repository's main>` (the commit a real fetch would report)."""

    def __init__(self, forge: Any) -> None:
        self.forge = forge
        self.calls: list[dict[str, Any]] = []
        self.answers: list[str] = []

    def __call__(self, tenant_id: str, dest: Path, *, data_root: Path, **kw: Any) -> str:
        dest = Path(dest)
        self.calls.append({"tenant": str(tenant_id), "dest": dest, "data_root": Path(data_root), "kw": kw,
                           "was_empty_dir": dest.is_dir() and not dest.is_symlink() and not any(dest.iterdir())})
        if self.answers:
            return self.answers.pop(0)
        bare = self.forge.bare(f"{ORG}/{tenant_id}")
        tip = subprocess.run(["git", "-C", str(bare), "rev-parse", "main"], capture_output=True, text=True,  # noqa: S603, S607
                             check=True).stdout.strip()
        return f"ok {tip}"


class FetchWorld(LifecycleWorld):
    """`LifecycleWorld` whose host actor has the fetch seam (`fetch=`) in place of the first-publish seam."""

    def new_host(self, tenants: Any, **overrides: Any) -> Any:
        if not hasattr(self, "fetch"):
            self.fetch = RecordingFetch(self.forge)
        parts: dict[str, Any] = {
            "forge": self.forge.client(None), "openbao_login": self.openbao.client(None), "git": self.git, "fetch": self.fetch,
            "config": self.config, "clock": self.clock, **overrides}
        return HostActor(tenants, **parts)
