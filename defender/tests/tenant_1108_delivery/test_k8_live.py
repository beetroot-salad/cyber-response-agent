"""K8 (amendment 2's deferred claim, an executed check in P3's contract): a host-made copy
under `<T>/` is a bind source the daemon resolves, under docker-outside-of-Docker included.

Live only (`pytest.mark.live`; CI's `-m "not live"` never runs it). It needs a reachable
daemon, `DEFENDER_K8_DATA_ROOT` naming the host's real data root (in the devcontainer,
`/workspace/.defender-data`; the suite's autouse fixtures replace `DEFENDER_DATA_ROOT` itself
with a temporary folder for every test, so it cannot carry this), this tree's box image and
the box runtime registered; otherwise it skips, naming what is missing, as it does when this
tree itself is not on a path the daemon shares (its `code` mount could not bind, whatever the
copy's location). Unlike the other live box suites it does not skip under DooD: DooD is the
topology K8 asks about. It writes only a fresh `k8-<random>` folder there, and removes it.
Run it with:

    DEFENDER_K8_DATA_ROOT=/workspace/.defender-data PYTHONPATH="$PWD" \\
        defender/.venv/bin/python -m pytest -m live \\
        defender/tests/tenant_1108_delivery/test_k8_live.py

Completion: it passes (a box started on the copy, the copy's token read back from inside the
box). A `BoxFault` naming the bind (C46/DooD) means the copy location must move before P4."""
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
    """K8: a copy made under `<data root>/<T>/drafts/<batch>/`, mounted `staged`
    beside the `code` tree, starts a real box: the token the start planted at the copy's
    root is read back from inside, so the daemon bound this very folder. Nothing is left."""
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
