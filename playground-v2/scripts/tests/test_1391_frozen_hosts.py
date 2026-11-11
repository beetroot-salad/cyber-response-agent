"""#1391 r6 O9: the frozen engine serves host-state from the freeze's own hosts.

Driven through `LabOps`' `run=` seam with a scripted docker (no lab): which hosts are served, how
each replica is started, what is cached and by what key, the endpoint-query service's two inputs,
the edge as the frontend, and teardown.
"""
from __future__ import annotations

import hashlib
import importlib.util
import subprocess
from pathlib import Path

import pytest

LAB_OPS = Path(__file__).resolve().parents[1] / "lab_ops.py"
_spec = importlib.util.spec_from_file_location("lab_ops_1391_frozen", LAB_OPS)
lab_ops = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lab_ops)

HOSTS = ["db-1", "web-1"]
SHA = {h: f"{i}{'f' * 63}" for i, h in enumerate(HOSTS)}


class Docker:
    """Records argv and the bytes each call was handed; answers `image inspect`/`test -f` from
    what it was told is cached."""

    def __init__(self, cached_images=(), done=()):
        self.calls, self.cached_images, self.done = [], set(cached_images), set(done)

    def __call__(self, argv, **kw):
        data = kw.get("input")
        if data is None and hasattr(kw.get("stdin"), "read"):
            data = kw["stdin"].read()
        self.calls.append((list(argv), data))
        rc, out = 0, ""
        if "inspect" in argv and "{{.State.Running}}" in argv:
            out = "true"
        elif argv[-3:-1] == ["image", "inspect"] and "-f" not in argv:
            rc = 0 if argv[-1] in self.cached_images else 1
        elif "test" in argv and "-f" in argv:
            rc = 0 if argv[-1] in self.done else 1
        return subprocess.CompletedProcess(argv, rc, stdout=out, stderr="")

    def inner(self, verb):
        """The engine's own docker commands of `verb` (after `exec [-i] lab-engine docker`)."""
        found = []
        for argv, data in self.calls:
            if "docker" in argv[3:] and lab_ops.ENGINE in argv:
                rest = argv[argv.index("docker", 3) + 1:]
                if rest and rest[0] == verb:
                    found.append((rest, data))
        return found


def freeze(hosts=HOSTS, drop=()):
    parts = {"stubs.tar": "s" * 64}
    for h in hosts:
        for name in lab_ops.LabOps.host_parts(h).values():
            parts[name] = SHA[h] if name.startswith("image-") else hashlib.sha256(name.encode()).hexdigest()
    for name in drop:
        parts.pop(name)
    return {"parts": parts}


@pytest.fixture
def parts(tmp_path):
    for h in HOSTS:
        for name in lab_ops.LabOps.host_parts(h).values():
            (tmp_path / name).write_bytes(f"bytes of {name}".encode())
    return tmp_path


def test_the_served_hosts_are_the_freezes_committed_images_not_todays_inventory(parts):
    docker = Docker()
    ops = lab_ops.LabOps(run=docker)
    assert ops.serve_hosts(parts, freeze()) == HOSTS
    started = {r[r.index("--name") + 1] for r, _ in docker.inner("run") if "-d" in r}
    assert set(HOSTS) <= started


@pytest.mark.parametrize("missing", ["image", "tree", "/var/log", "/var/lib/elastic-agent"])
def test_a_freeze_missing_a_hosts_part_is_refused_before_anything_starts(parts, missing):
    docker = Docker()
    with pytest.raises(lab_ops.LabOpsError):
        lab_ops.LabOps(run=docker).serve_hosts(parts, freeze(drop=[lab_ops.LabOps.host_parts("web-1")[missing]]))
    assert not docker.inner("run")


def test_a_freeze_with_no_host_image_is_refused():
    with pytest.raises(lab_ops.LabOpsError, match="no host image"):
        lab_ops.LabOps(run=Docker()).serve_hosts(Path("/nonexistent"), {"parts": {"stubs.tar": "x"}})


def test_each_replica_is_inert_networkless_and_answers_ps_from_its_captured_tree(parts):
    docker = Docker()
    lab_ops.LabOps(run=docker).serve_hosts(parts, freeze())
    runs = {r[r.index("--name") + 1]: r for r, _ in docker.inner("run") if "-d" in r}
    for host in HOSTS:
        argv = runs[host]
        opts = " ".join(argv)
        assert "--network none" in opts and "--no-healthcheck" in argv
        assert argv[argv.index("--entrypoint") + 1] == "sleep" and argv[-1] == "infinity"
        assert f"{lab_ops.HOST_SHIM_DIR}/ps:/usr/local/bin/ps:ro" in argv
        assert f"V2_PS_SHIM_TREE={lab_ops.REPLICA_TREE_DIR}/tree.txt" in argv
        for mount in (*lab_ops.HOST_VOLUMES, lab_ops.REPLICA_TREE_DIR):
            assert any(a.endswith(f":{mount}:ro") for a in argv), (host, mount)
        assert argv[-2] == f"frozen-host/{host}:{SHA[host][:16]}"
    shim = [d for a, d in docker.calls if any("chmod 0755" in x for x in a)]
    assert shim == [(lab_ops.PLAYGROUND / "hosts" / "base" / "ps-shim").read_bytes()], "today's shim"


def test_an_image_is_loaded_streamed_and_retagged_by_its_parts_digest(parts):
    docker = Docker()
    lab_ops.LabOps(run=docker).serve_hosts(parts, freeze())
    loads = docker.inner("load")
    assert [d for _, d in loads] == [f"bytes of image-{h}.tar".encode() for h in HOSTS]
    tags = [r for r, _ in docker.inner("tag")]
    assert tags == [["tag", f"local/{h}:latest", f"frozen-host/{h}:{SHA[h][:16]}"] for h in HOSTS]


def test_cached_images_and_finished_extracts_are_not_redone(parts):
    f = freeze()
    keys = {lab_ops.LabOps._key(d) for n, d in f["parts"].items() if not n.startswith("image-")}
    docker = Docker(cached_images={f"frozen-host/{h}:{SHA[h][:16]}" for h in HOSTS},
                    done={f"{lab_ops.HOST_PARTS_DIR}/{k}.done" for k in keys})
    lab_ops.LabOps(run=docker).serve_hosts(parts, f)
    assert not docker.inner("load") and not docker.inner("tag")
    assert not [r for r, _ in docker.inner("run") if "--rm" in r], "an extract was redone"


def test_an_extract_is_marked_done_only_after_it_ran(parts):
    docker = Docker()
    lab_ops.LabOps(run=docker).serve_hosts(parts, freeze())
    order = [" ".join(a) for a, _ in docker.calls]
    for i, line in enumerate(order):
        if "printf done >" in line:
            assert "--rm" in order[i - 1] and "/dst" in order[i - 1]


def test_the_service_answers_the_freezes_hosts_with_nothing_inspectable(parts):
    docker = Docker()
    lab_ops.LabOps(run=docker).serve_hosts(parts, freeze())
    lists = [d for a, d in docker.calls if d is not None and any("inspectable.txt" in x for x in a)]
    assert lists == ["db-1\nweb-1\n"]
    assert any("printf '' > " in x and "inspectable.txt" in x for a, _ in docker.calls for x in a)
    service = [r for r, _ in docker.inner("run") if lab_ops.QUERY_IMAGE in r]
    assert service and "/var/run/docker.sock:/var/run/docker.sock" in service[0]


def test_the_frontend_is_the_edge_on_every_surface_port_without_the_key():
    docker = Docker()
    ops = lab_ops.LabOps(run=docker)
    ops._frontends()
    run = [r for r, _ in docker.inner("run")]
    assert len(run) == 1 and lab_ops.EDGE_IMAGE in run[0] and run[0][-1] == "--no-key-check"
    published = {r for i, r in enumerate(run[0]) if run[0][i - 1] == "-p"}
    assert published == {f"{p}:{p}" for p in lab_ops.FRONTEND_PORTS}
    assert lab_ops.HOST_STATE_PORT in lab_ops.FRONTEND_PORTS


def test_teardown_removes_the_replicas_the_service_and_the_frontend(parts):
    docker = Docker()
    ops = lab_ops.LabOps(run=docker)
    ops.serve_hosts(parts, freeze())
    ops.teardown()
    removed = {n for r, _ in docker.inner("rm") for n in r[2:]}
    assert {*HOSTS, lab_ops.HOST_STATE_SERVICE, lab_ops.FRONTEND} <= removed


def test_purge_removes_a_freezes_images_and_extracts(parts):
    docker = Docker()
    f = freeze()
    lab_ops.LabOps(run=docker).purge_host_cache(f)
    images = {r[-1] for r, _ in docker.inner("image") if r[1] == "rm"}
    assert images == {f"frozen-host/{h}:{SHA[h][:16]}" for h in HOSTS}
    volumes = {r[-1] for r, _ in docker.inner("volume")}
    assert len(volumes) == 3 * len(HOSTS)
