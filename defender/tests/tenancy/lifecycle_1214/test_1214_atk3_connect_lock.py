"""#1214 attack-3 hole 9 (P3, RC-5): the connect command's `update` and `propose` hold the tenant's host lock
shared and record themselves like `check` does, so teardown finds and stops them mid-publish or mid-PR.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.tenancy.lifecycle_1214.test_1214_host_lock import REPO_ROOT, world  # noqa: E402, F401 — fixture

LAUNCHER = textwrap.dedent("""
    import os, pathlib, sys, time
    verb, tenant, ready, staged = sys.argv[1:5]
    from defender.tenancy import TenantDirectory

    class Blocking(TenantDirectory):
        def __init__(self):
            super().__init__(lambda: None)
        def state(self, tenant_id):
            pathlib.Path(ready).write_text(str(os.getpid()))
            time.sleep(600)
        def forge_wiring(self, tenant_id):
            time.sleep(600)

    from defender.cli import tenant as connect
    connect.main([verb, tenant, *([staged] if verb == "propose" else [])], directory=Blocking())
""")


class Holder:
    """A `tenant.py <verb>` child sitting right after its lock-and-registry step, in the state check."""

    def __init__(self, tmp_path: Path, tenant: str, verb: str) -> None:
        self.ready = tmp_path / f"ready-{verb}"
        staged = tmp_path / "staged"
        staged.mkdir(exist_ok=True)
        (staged / "note.md").write_text("note\n", encoding="utf-8")
        self.proc = subprocess.Popen([sys.executable, "-c", LAUNCHER, verb, tenant, str(self.ready), str(staged)],  # noqa: S603
                                     env={**os.environ, "PYTHONPATH": str(REPO_ROOT)}, cwd=REPO_ROOT,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 60
        while not self.ready.exists():
            if self.proc.poll() is not None or time.monotonic() > deadline:
                self.proc.kill()
                raise AssertionError(f"the child never reached the state check:\n{self.proc.communicate()}")
            time.sleep(0.05)

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.communicate()


@pytest.mark.parametrize("verb", ["update", "propose"])
def test_teardown_terminates_a_running_update_or_propose(world, tmp_path, verb):  # noqa: F811
    """Teardown SIGTERMs the `update`/`propose` it finds recorded and then removes the folder (P3, O4)."""
    tenant = world.active_tenant()
    holder = Holder(tmp_path, tenant, verb)
    try:
        assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
        world.drive()
        assert holder.proc.wait(timeout=30) == -signal.SIGTERM
        assert world.item(tenant)["state"] == "offboarded"
        assert not (world.data_root / tenant).exists()
    finally:
        holder.kill()
