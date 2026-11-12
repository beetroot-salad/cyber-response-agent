"""#1391 r6 O9: the frozen engine serves host-state from the freeze's own hosts.

Driven through `LabOps`' `run=` seam with a scripted docker (no lab): which hosts are served, how
each replica image is built and from what, what is cached and by what key, how each replica is
started, the endpoint-query service's two inputs, the edge as the frontend, and teardown.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import shlex
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

    def __init__(self, cached=(), *, engine=True, labelled=()):
        self.calls, self.cached, self.engine, self.labelled = [], set(cached), engine, dict(labelled)

    def __call__(self, argv, **kw):
        data = kw.get("input")
        if data is None and hasattr(kw.get("stdin"), "read"):
            data = kw["stdin"].read()
        self.calls.append((list(argv), data))
        rc, out = 0, ""
        if "inspect" in argv and "{{.State.Running}}" in argv:
            rc, out = (0, "true") if self.engine else (1, "")
        elif "image" in argv and "ls" in argv and "--filter" in argv:
            label = argv[argv.index("--filter") + 1]
            out = "\n".join(sorted(self.labelled.get(label, ())))
        elif "image" in argv and "ls" in argv:
            out = "\n".join(sorted(self.cached))
        elif "image" in argv and "inspect" in argv and "{{.Id}}" in argv:
            out = "sha256:" + "ab" * 32     # an image's id on the lab server (#1391: the copy's marker names it)
        elif "image" in argv and "inspect" in argv and "-f" not in argv:
            # the engine's copies of the lab's own images are current here (their marker tests are on the rig)
            rc = 0 if argv[-1] in self.cached or "-lab-" in argv[-1] else 1
        return subprocess.CompletedProcess(argv, rc, stdout=out, stderr="")

    def inner(self, verb):
        """The engine's own docker commands of `verb`: `exec [-i] lab-engine docker ...`, or one
        command of an engine script (`exec lab-engine sh -c '...; docker ... && docker ...'`)."""
        found = []
        for argv, data in self.calls:
            if lab_ops.ENGINE not in argv:
                continue
            if "docker" in argv[3:]:
                rest = argv[argv.index("docker", 3) + 1:]
                if rest and rest[0] == verb:
                    found.append((rest, data))
            elif argv[-2:-1] == ["-c"]:
                for words in self.script_commands(argv[-1]):
                    if words[:2] == ["docker", verb]:
                        found.append((words[1:], None))
        return found

    @staticmethod
    def script_commands(script):
        lex = shlex.shlex(script, posix=True, punctuation_chars=";&|<>")
        lex.whitespace_split = True
        commands, words = [], []
        for token in lex:
            if token in (";", "&&", "||"):
                commands.append(words)
                words = []
            else:
                words.append(token)
        return [*commands, words]

    def engine_execs(self):
        return [argv for argv, _ in self.calls if lab_ops.ENGINE in argv and "exec" in argv]


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


def test_a_replica_image_holds_its_volume_copies_as_captured_its_tree_and_todays_shim(parts):
    docker = Docker()
    lab_ops.LabOps(run=docker).serve_hosts(parts, freeze())
    copies = docker.inner("cp")
    assert len(copies) == 3 * len(HOSTS)
    shim = (lab_ops.PLAYGROUND / "hosts" / "base" / "ps-shim").read_bytes()
    for host in HOSTS:
        mine = {argv[3]: data for argv, data in copies if argv[3].startswith(f"frozen-build-{host}:")}
        assert all(argv[:3] == ["cp", "-a", "-"] for argv, _ in copies)
        for mount in lab_ops.HOST_VOLUMES:
            part = parts / lab_ops.LabOps.host_parts(host)[mount]
            assert mine[f"frozen-build-{host}:{mount}"] == part.read_bytes(), "the copy as captured, unrewritten"
        members = _members(mine[f"frozen-build-{host}:/"])
        assert set(members) == {"usr/local/bin/ps", "lab/tree/tree.txt"}
        assert members["usr/local/bin/ps"][1] == shim and members["usr/local/bin/ps"][0].mode == 0o755
        assert members["lab/tree/tree.txt"][1] == f"bytes of proc-tree-{host}.txt".encode()


def test_a_replica_image_is_committed_idle_labelled_and_only_after_its_content_is_in(parts):
    docker = Docker()
    f = freeze()
    lab_ops.LabOps(run=docker).serve_hosts(parts, f)
    commits = [r for r, _ in docker.inner("commit")]
    assert [c[-1] for c in commits] == [lab_ops.LabOps.replica_tag(f["parts"], h) for h in HOSTS]
    for host, c in zip(HOSTS, commits):
        assert {'--change=ENTRYPOINT ["sleep"]', '--change=CMD ["infinity"]', "--change=HEALTHCHECK NONE",
                f"--change=ENV V2_PS_SHIM_TREE={lab_ops.REPLICA_TREE_DIR}/tree.txt",
                f"--change=LABEL {lab_ops.BASE_LABEL}=frozen-host-base/{host}:{SHA[host][:16]}"} <= set(c)
    order = [(a[a.index("docker", 3) + 1], a) for a, _ in docker.calls if "docker" in a[3:]]
    for host in HOSTS:
        build = f"frozen-build-{host}"
        steps = [verb for verb, a in order if build in " ".join(a) and verb in ("run", "cp", "commit")]
        assert steps == ["run", "cp", "cp", "cp", "commit"], (host, steps)
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


def test_the_service_answers_the_freezes_hosts_with_nothing_inspectable(parts):
    docker = Docker()
    lab_ops.LabOps(run=docker).serve_hosts(parts, freeze())
    lists = [d for a, d in docker.calls if d is not None and any("inspectable.txt" in x for x in a)]
    assert lists == ["db-1\nweb-1\n"]
    assert any("printf '' > " in x and "inspectable.txt" in x for a, _ in docker.calls for x in a)
    service = [r for r, _ in docker.inner("run") if lab_ops.QUERY_IMAGE in r]
    assert service and "/var/run/docker.sock:/var/run/docker.sock" in service[0]
    assert "--init" in service[0], "PID 1 must answer a stop"


def test_the_service_is_handed_todays_ps_argv_not_the_one_baked_into_its_image(parts):
    """#1391: the replica shim answers only the surface's argv, so the launcher passes that argv to
    the service rather than trust a possibly older image's own copy."""
    import json
    docker = Docker()
    lab_ops.LabOps(run=docker).serve_hosts(parts, freeze())
    service = [r for r, _ in docker.inner("run") if lab_ops.QUERY_IMAGE in r][0]
    i = service.index("--ps-argv")
    assert json.loads(service[i + 1]) == lab_ops.PS_ARGV


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


def test_purge_removes_every_replica_built_from_a_freezes_host_images_whatever_built_it():
    """Replica images built under an older shim or recipe carry the same label: they go too."""
    f = freeze()
    labelled = {f"label={lab_ops.BASE_LABEL}=frozen-host-base/{h}:{SHA[h][:16]}":
                [f"frozen-host/{h}:old0old0old0old0", lab_ops.LabOps.replica_tag(f["parts"], h)] for h in HOSTS}
    docker = Docker(labelled=labelled)
    removed = lab_ops.LabOps(run=docker).purge_host_cache(f)
    images = [r[-1] for r, _ in docker.inner("image") if r[1] == "rm"]
    want = {t for tags in labelled.values() for t in tags} | {f"frozen-host-base/{h}:{SHA[h][:16]}" for h in HOSTS}
    assert set(images) == want and set(removed) == want
    for h in HOSTS:
        base = f"frozen-host-base/{h}:{SHA[h][:16]}"
        assert images.index(base) > max(images.index(t) for t in labelled[f"label={lab_ops.BASE_LABEL}={base}"]), \
            "the host image goes after the replicas built on it"


def test_purge_with_no_engine_removes_nothing_and_creates_none():
    docker = Docker(engine=False)
    assert lab_ops.LabOps(run=docker).purge_host_cache(freeze()) == []
    assert len(docker.calls) == 1, docker.calls


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


def test_serving_cached_hosts_takes_the_same_round_trips_whatever_the_host_count(parts):
    """Each engine call is a round trip over the lab's SSH context: the replica starts, the
    host lists and the service start are one exec, so a cached launch costs the same for 1 host
    as for many."""
    counts = {}
    for hosts in (HOSTS[:1], HOSTS):
        f = freeze(hosts=hosts)
        docker = Docker(cached={lab_ops.LabOps.replica_tag(f["parts"], h) for h in hosts})
        lab_ops.LabOps(run=docker).serve_hosts(parts, f)
        counts[len(hosts)] = len(docker.calls)
        batch = [a for a in docker.engine_execs() if a[-2:-1] == ["-c"] and "docker run" in a[-1]]
        assert len(batch) == 1, "the starts are not one exec"
        started = {w[w.index("--name") + 1] for w in Docker.script_commands(batch[0][-1]) if w[:2] == ["docker", "run"]}
        assert started == {*hosts, lab_ops.HOST_STATE_SERVICE}
    assert counts[1] == counts[len(HOSTS)], counts


def _compose_runs() -> bool:
    try:
        return subprocess.run(["docker", "compose", "version"], capture_output=True).returncode == 0
    except OSError:
        return False


@pytest.mark.skipif(not _compose_runs(), reason="needs the docker compose CLI (no daemon)")
@pytest.mark.parametrize("written,password", [('"pw-1"', "pw-1"), ("pw-1 # rotated today", "pw-1"),
                                              ("'pw-1'", "pw-1"), ("pw-1   ", "pw-1"),
                                              ("'pw$1'", "pw$1")])   # compose prints a `$` as `$$`
def test_the_launcher_reads_the_password_as_compose_gives_it_to_es_init_not_as_the_line_is_written(
        tmp_path, monkeypatch, written, password):
    """#1391: real compose renders the lab's own compose.yml, so a quoted, commented or padded
    value is the password es-init sets, and an operator's stale export is not consulted."""
    playground = Path(lab_ops.PLAYGROUND)
    (tmp_path / "soar").mkdir()
    (tmp_path / "compose.yml").write_text((playground / "compose.yml").read_text())
    (tmp_path / "soar" / "compose.yml").write_text((playground / "soar" / "compose.yml").read_text())
    lines = [line for line in (playground / ".env.example").read_text().splitlines()
             if not line.startswith(f"{lab_ops.READONLY_PASSWORD_ENV}=")]
    (tmp_path / ".env").write_text("\n".join([*lines, f"{lab_ops.READONLY_PASSWORD_ENV}={written}", ""]))
    monkeypatch.setenv(lab_ops.READONLY_PASSWORD_ENV, "stale-exported-password")
    monkeypatch.setenv("DOCKER_HOST", "unix:///nonexistent.sock")   # config needs no daemon; never reach one
    ops = lab_ops.LabOps(run=subprocess.run, lab_env_file=tmp_path / ".env")
    assert ops.current_password() == password


def _saved(rig) -> list[str]:
    """The lab-server images copied into the engine, in order (`docker save <image>` on the lab server)."""
    return [argv[-1] for argv, _ in rig.docker.calls if "save" in argv and "exec" not in argv]


def test_an_engine_copy_of_a_lab_image_is_current_by_its_marker_and_recopied_when_the_lab_rebuilds_it(tmp_path):
    """#1391: every image the engine runs is the lab server's current one. A copy is marked with the
    lab server's image id (the two daemons' own ids differ for one image), so an unchanged image is
    copied once, a rebuild under the same tag is copied again, and the older marker is dropped."""
    from _lab_fakes import LabRig
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    rig.launch()
    first = _saved(rig)
    assert {lab_ops.EDGE_IMAGE, lab_ops.QUERY_IMAGE, "soc-playground/cmdb:local"} <= set(first), first
    rig.launch()
    assert _saved(rig) == first, "an unchanged image is not copied again"
    rig.docker.image_rev[lab_ops.QUERY_IMAGE] = 1
    rig.launch()
    assert _saved(rig)[len(first):] == [lab_ops.QUERY_IMAGE]
    repo = lab_ops.QUERY_IMAGE.rpartition(":")[0]
    markers = sorted(t for _, t in rig.docker.markers if t.startswith(f"{repo}:"))
    assert len(markers) == 1 and markers[0].startswith(f"{repo}:local-lab-"), markers
