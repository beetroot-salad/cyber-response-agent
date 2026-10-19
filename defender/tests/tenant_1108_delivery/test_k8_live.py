from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from defender.runtime import box
from defender.tests._docker import daemon_reachable, docker_runtimes, dood_anchor, is_dood

from ._support import DEFENDER

pytestmark = pytest.mark.live

#: The host's real data root, for this check only (see the module docstring).
K8_ROOT_ENV = "DEFENDER_K8_DATA_ROOT"


def _live_spec():
    """The box spec a live run uses here, or a skip naming what this host lacks."""
    if not daemon_reachable():
        pytest.skip("K8 needs a reachable docker daemon")
    root = os.environ.get(K8_ROOT_ENV)
    if not root or not Path(root).is_dir():
        pytest.skip(f"K8 needs {K8_ROOT_ENV} naming the host's data root")
    if is_dood() and dood_anchor() is None:
        pytest.skip("this tree is not on a path the daemon shares, so its `code` mount cannot "
                    "bind; K8 asks about the copy, so run it from a tree under /workspace")
    spec = dataclasses.replace(box.BoxSpec.from_env(os.environ), rootfs=box.image_tag(DEFENDER))
    if spec.runtime not in docker_runtimes():
        pytest.skip(f"K8 needs the {spec.runtime!r} runtime registered with the daemon")
    present = subprocess.run(["docker", "image", "inspect", spec.rootfs], capture_output=True,
                             timeout=60, check=False)
    if present.returncode != 0:
        pytest.skip(f"K8 needs this tree's box image {spec.rootfs} built")
    return Path(root), spec


def test_a_host_made_copy_under_the_tenant_folder_binds_into_a_real_box(monkeypatch):
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    data_root, spec = _live_spec()
    tenant_dir = data_root / f"k8-{uuid.uuid4().hex[:12]}"
    copy = tenant_dir / "drafts" / "k8"
    try:
        (copy / "agent" / "lessons").mkdir(parents=True)
        (copy / "agent" / "lessons" / "probe.md").write_text("k8\n", encoding="utf-8")
        request = box.BoxRequest(
            name=f"defender-{tenant_dir.name}", workdir=copy / "agent", env={}, spec=spec,
            defender_dir=DEFENDER,
            mounts=(box.Mount(source=DEFENDER, target=DEFENDER, kind="code"),
                    box.Mount(source=copy, target=copy, kind="staged")))
        executor = box.start_box(request)
        try:
            assert executor.sandboxed, "the start fell back to the host instead of a box"
        finally:
            box.stop_box(executor)
    finally:
        shutil.rmtree(tenant_dir, ignore_errors=True)
