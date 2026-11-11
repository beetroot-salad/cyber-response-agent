"""#1391 r6 O9: the frozen engine serves host-state from the freeze's own hosts.

Driven through `LabOps`' `run=` seam with a scripted docker (no lab): which hosts are served, how
each replica image is built and from what, what is cached and by what key, how each replica is
started, the endpoint-query service's two inputs, the edge as the frontend, and teardown.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import subprocess
import tarfile
from pathlib import Path

import pytest

LAB_OPS = Path(__file__).resolve().parents[1] / "lab_ops.py"
_spec = importlib.util.spec_from_file_location("lab_ops_1391_frozen", LAB_OPS)
lab_ops = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lab_ops)

HOSTS = ["db-1", "web-1"]
SHA = {h: f"{i}{'f' * 63}" for i, h in enumerate(HOSTS)}


class Docker:
    """Records argv and the bytes each call was handed; answers `image ls`/`image inspect` from
    what it was told is cached."""

    def __init__(self, cached=()):
        self.calls, self.cached = [], set(cached)

    def __call__(self, argv, **kw):
        data = kw.get("input")
        if data is None and hasattr(kw.get("stdin"), "read"):
            data = kw["stdin"].read()
        self.calls.append((list(argv), data))
        rc, out = 0, ""
        if "inspect" in argv and "{{.State.Running}}" in argv:
            out = "true"
        elif "image" in argv and "ls" in argv:
            out = "\n".join(sorted(self.cached))
        elif "image" in argv and "inspect" in argv and "-f" not in argv:
            rc = 0 if argv[-1] in self.cached else 1
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


def _tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        dot = tarfile.TarInfo(".")
        dot.type, dot.mode = tarfile.DIRTYPE, 0o755
        t.addfile(dot)
        for name, data in files.items():
            info = tarfile.TarInfo(f"./{name}")
            info.size, info.uid = len(data), 1000
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


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
        for kind, name in lab_ops.LabOps.host_parts(h).items():
            if kind in lab_ops.HOST_VOLUMES:
                data = _tar({f"{h}{kind.replace('/', '-')}.log": f"content of {h} {kind}".encode()})
            else:
                data = f"bytes of {name}".encode()
            (tmp_path / name).write_bytes(data)
    return tmp_path


def _members(data):
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        return {m.name: (m, t.extractfile(m).read() if m.isfile() else None) for m in t.getmembers()}


def test_the_served_hosts_are_the_freezes_committed_images_not_todays_inventory(parts):
    docker = Docker()
    assert lab_ops.LabOps(run=docker).serve_hosts(parts, freeze()) == HOSTS
    started = {r[r.index("--name") + 1] for r, _ in docker.inner("run") if "-d" in r}
    assert set(HOSTS) <= started


@pytest.mark.parametrize("missing", ["image", "tree", "/var/log", "/var/lib/elastic-agent"])
def test_a_freeze_missing_a_hosts_part_is_refused_before_anything_starts(parts, missing):
    docker = Docker()
    f = freeze(drop=[lab_ops.LabOps.host_parts("web-1")[missing]])
    with pytest.raises(lab_ops.LabOpsError, match="lacks host parts"):
        lab_ops.LabOps.check_host_parts(f)
    with pytest.raises(lab_ops.LabOpsError):
        lab_ops.LabOps(run=docker).serve_hosts(parts, f)
    assert not docker.calls


def test_a_freeze_with_no_host_image_is_refused():
    with pytest.raises(lab_ops.LabOpsError, match="no host image"):
        lab_ops.LabOps.check_host_parts({"parts": {"stubs.tar": "x"}})


def test_each_replica_runs_its_own_image_inert_networkless_and_read_only(parts):
    docker = Docker()
    f = freeze()
    lab_ops.LabOps(run=docker).serve_hosts(parts, f)
    runs = {r[r.index("--name") + 1]: r for r, _ in docker.inner("run") if "-d" in r}
    for host in HOSTS:
        argv = runs[host]
        assert "--network none" in " ".join(argv)
        assert "--no-healthcheck" in argv and "--read-only" in argv
        assert argv[-1] == lab_ops.LabOps.replica_tag(f["parts"], host)
        assert not [a for a in argv if a == "-v"], "a replica mounts nothing: its image holds it all"


def test_a_replica_image_holds_its_volume_copies_its_tree_and_todays_shim(parts):
    docker = Docker()
    f = freeze()
    lab_ops.LabOps(run=docker).serve_hosts(parts, f)
    overlays = docker.inner("cp")
    assert len(overlays) == len(HOSTS)
    shim = (lab_ops.PLAYGROUND / "hosts" / "base" / "ps-shim").read_bytes()
    for host, (argv, data) in zip(HOSTS, overlays):
        assert argv[:3] == ["cp", "-a", "-"] and argv[3] == f"frozen-build-{host}:/"
        members = _members(data)
        assert members["usr/local/bin/ps"][1] == shim and members["usr/local/bin/ps"][0].mode == 0o755
        assert members["lab/tree/tree.txt"][1] == f"bytes of proc-tree-{host}.txt".encode()
        for mount in lab_ops.HOST_VOLUMES:
            rel = mount.lstrip("/")
            log = members[f"{rel}/{host}{mount.replace('/', '-')}.log"]
            assert log[1] == f"content of {host} {mount}".encode() and log[0].uid == 1000
            assert members[rel][0].isdir()


def test_a_replica_image_is_committed_idle_and_only_after_its_content_is_in(parts):
    docker = Docker()
    f = freeze()
    lab_ops.LabOps(run=docker).serve_hosts(parts, f)
    commits = [r for r, _ in docker.inner("commit")]
    assert [c[-1] for c in commits] == [lab_ops.LabOps.replica_tag(f["parts"], h) for h in HOSTS]
    for c in commits:
        assert {'--change=ENTRYPOINT ["sleep"]', '--change=CMD ["infinity"]', "--change=HEALTHCHECK NONE",
                f"--change=ENV V2_PS_SHIM_TREE={lab_ops.REPLICA_TREE_DIR}/tree.txt"} <= set(c)
    order = [(a[a.index("docker", 3) + 1], a) for a, _ in docker.calls if "docker" in a[3:]]
    for host in HOSTS:
        build = f"frozen-build-{host}"
        steps = [verb for verb, a in order if build in " ".join(a) and verb in ("run", "cp", "commit")]
        assert steps == ["run", "cp", "commit"], (host, steps)
        clear = next(a for verb, a in order if verb == "run" and build in a)
        assert all(m in clear[-1] for m in lab_ops.HOST_VOLUMES) and "--network" in clear


def test_the_host_image_is_loaded_streamed_and_kept_under_its_parts_digest(parts):
    docker = Docker()
    lab_ops.LabOps(run=docker).serve_hosts(parts, freeze())
    assert [d for _, d in docker.inner("load")] == [f"bytes of image-{h}.tar".encode() for h in HOSTS]
    tags = [r for r, _ in docker.inner("tag")]
    assert tags == [["tag", f"local/{h}:latest", f"frozen-host-base/{h}:{SHA[h][:16]}"] for h in HOSTS]


def test_a_cached_replica_image_is_not_rebuilt(parts):
    f = freeze()
    docker = Docker(cached={lab_ops.LabOps.replica_tag(f["parts"], h) for h in HOSTS})
    lab_ops.LabOps(run=docker).serve_hosts(parts, f)
    for verb in ("load", "tag", "cp", "commit"):
        assert not docker.inner(verb), verb
    assert not [r for r, _ in docker.inner("run") if "-d" not in r], "a build container was started"


def test_the_replica_tag_follows_every_input(tmp_path, monkeypatch):
    f = freeze()
    tag = lab_ops.LabOps.replica_tag(f["parts"], "web-1")
    for kind, name in lab_ops.LabOps.host_parts("web-1").items():
        changed = dict(f["parts"], **{name: "0" * 64})
        assert lab_ops.LabOps.replica_tag(changed, "web-1") != tag, kind
    other = tmp_path / "ps"
    other.write_bytes(b"#!/bin/sh\necho another shim\n")
    monkeypatch.setattr(lab_ops, "PS_SHIM", other)
    assert lab_ops.LabOps.replica_tag(f["parts"], "web-1") != tag
    monkeypatch.undo()
    monkeypatch.setattr(lab_ops, "REPLICA_RECIPE", "replica-v999")
    assert lab_ops.LabOps.replica_tag(f["parts"], "web-1") != tag


def test_a_volume_copy_reaching_outside_its_mount_is_refused(parts):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo("../etc/shadow")
        info.size = 1
        t.addfile(info, io.BytesIO(b"x"))
    (parts / lab_ops.LabOps.host_parts("db-1")["/var/log"]).write_bytes(buf.getvalue())
    docker = Docker()
    with pytest.raises(lab_ops.LabOpsError, match="outside its mount"):
        lab_ops.LabOps(run=docker).serve_hosts(parts, freeze())
    assert not docker.inner("commit")


def test_the_service_answers_the_freezes_hosts_with_nothing_inspectable(parts):
    docker = Docker()
    lab_ops.LabOps(run=docker).serve_hosts(parts, freeze())
    lists = [d for a, d in docker.calls if d is not None and any("inspectable.txt" in x for x in a)]
    assert lists == ["db-1\nweb-1\n"]
    assert any("printf '' > " in x and "inspectable.txt" in x for a, _ in docker.calls for x in a)
    service = [r for r, _ in docker.inner("run") if lab_ops.QUERY_IMAGE in r]
    assert service and "/var/run/docker.sock:/var/run/docker.sock" in service[0]
    assert "--init" in service[0], "PID 1 must answer a stop"


def test_the_frontend_is_the_edge_on_every_surface_port_without_the_key():
    docker = Docker()
    lab_ops.LabOps(run=docker)._frontends()
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


def test_purge_removes_a_freezes_replica_and_host_images():
    docker = Docker()
    f = freeze()
    lab_ops.LabOps(run=docker).purge_host_cache(f)
    images = {r[-1] for r, _ in docker.inner("image") if r[1] == "rm"}
    assert images == ({lab_ops.LabOps.replica_tag(f["parts"], h) for h in HOSTS}
                      | {f"frozen-host-base/{h}:{SHA[h][:16]}" for h in HOSTS})


@pytest.mark.parametrize("dropped", ["all", "one"])
def test_the_launcher_refuses_a_freeze_without_complete_host_parts_before_any_lab_traffic(tmp_path, dropped):
    """The refusal belongs with the launcher's other pre-launch checks: no lock, no restore."""
    import yaml
    from _lab_fakes import FROZEN_HOST, LabRig

    rig = LabRig(tmp_path)
    named = lab_ops.LabOps.host_parts(FROZEN_HOST)
    gone = list(named.values()) if dropped == "all" else [named["/var/log"]]
    for name in gone:
        rig.freeze["parts"].pop(name)
        (rig.parts / rig.freeze_dir.name / name).unlink()
    (rig.freeze_dir / "freeze.yaml").write_text(yaml.safe_dump(rig.freeze))
    rig.write_expected_case("none")
    with pytest.raises(Exception, match="no host image" if dropped == "all" else "lacks host parts") as caught:
        rig.launch()
    assert type(caught.value).__name__ == "LaunchRefused"
    assert rig.docker.calls == [] and not rig.cluster.requests
    assert "frozen-engine" not in rig.store.records
