"""#1618 (flow 5, D9, D10): the readiness helper reads the tenant's knowledge through the fetch child, not the launch-time publish.

FORCED: the seam `job_host.main(..., fetch=)` replaces `publish=` (the design names no seam). It is called
`fetch(tenant_id, dest, *, data_root, **_)` with `dest` an empty folder the helper made, and answers the child's one report line:
`ok <commit>` (the folder then holds `agent/` and `settings/` at that commit) or `refused <transient|lasting> <reason>`. The FORCED
`client=` seam (the forge client the drain's delivery uses, `job_host.main(client=)`) carries the branch-protection check (D9).
`readiness_fetching` is `_readiness1471.readiness` with that seam in place of `publish` (which `drive_helper` always adds)."""
from __future__ import annotations

import contextlib
import io
import shutil
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender.tests.support.jobs._job_helper import ContainerStandIn, HelperRan, HelperScene, make_signer
from defender.tests.support.jobs._readiness1471 import Readied, entry_of


class ScriptedFetch:
    """Records each call (tenant, destination, the destination's state at the call, the keywords) and answers the queued `answers`,
    else `ok <the scene's published commit>` after filling `dest` with the scene's published `agent/` and `settings/`."""

    def __init__(self, scene: HelperScene) -> None:
        self.scene = scene
        self.calls: list[dict[str, Any]] = []
        self.answers: list[str] = []

    def __call__(self, tenant_id: str, dest: Path, *, data_root: Path, **kw: Any) -> str:
        dest = Path(dest)
        self.calls.append({"tenant": str(tenant_id), "dest": dest, "kw": kw,
                           "was_empty_dir": dest.is_dir() and not dest.is_symlink() and not any(dest.iterdir())})
        if self.answers:
            return self.answers.pop(0)
        for half in ("agent", "settings"):
            shutil.copytree(Path(self.scene.t.clone) / half, dest / half, symlinks=True)
        return f"ok {self.scene.t.commit}"


def readiness_fetching(scene: HelperScene, *, fetch: Callable[..., str], client: Any = None, signer: Any = None,
                       rid: str | None = None, container: Callable[[Any], int] | None = None) -> Readied:
    """The helper for a readiness check of the scene's tenant with `fetch` (and `client`, when given) as its seams; like
    `_readiness1471.readiness` it never raises for the subject's absence."""
    from defender import job_host

    rid = rid or str(uuid.uuid4())
    done = Readied(scene, rid, HelperRan(), ContainerStandIn(), "")
    stand_in = ContainerStandIn()

    def captured(c: Any) -> int:
        with contextlib.suppress(Exception):
            done.facts = c.request("launch")
        return (container or entry_of(scene, rid, done))(c)

    stand_in.job = captured
    done.docker = stand_in
    seams: dict[str, Any] = {"fetch": fetch}
    if client is not None:
        seams["client"] = client
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        try:
            done.ran.rc = job_host.main(scene.argv("readiness", rid), docker=stand_in,
                                        signer=signer if signer is not None else make_signer(), **seams)
        except SystemExit as exited:
            done.ran.rc = exited.code if isinstance(exited.code, int) else 1
        except BaseException as crashed:  # noqa: BLE001 — kept for the case to name
            done.ran.raised = crashed
    done.err = err.getvalue()
    return done
