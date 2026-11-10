"""The docker the real lab layer (`lab_ops.LabOps`) talks to in the make-a-case and launcher rig (#1347 r6.4.3 C-rig).

`RigDocker` is a `run=` for the real `LabOps`: it answers `docker [--context C] <verb> ...` the way the docker
CLI does, for the verbs the lab uses, and records everything. It implements no lab policy: it does not know
what a marker, an offset or a variant is. What it models:

* Engines (scopes). `--context C` (or none: the deployment's own engine) is a scope. A container whose command
  runs `dockerd` is itself an engine: `exec <it> docker ...` acts on the scope `<C>/<name>`, which answers only
  while that container runs; when it stops, every container in its scope stops too.
* Containers: `run` (`-d` = running; foreground = runs its command and exits, `--rm` removes it), `create`,
  `start`, `restart`, `stop`, `kill`, `rm [-f] [-v]` (a running container needs `-f`; `-f` on a missing one is
  silent; `-v` removes its anonymous volumes only, as docker does), `inspect -f '{{.State.Running}}'`
  (prints `false`, rc 0, for a stopped container; rc 1 for a missing one) and `'{{.Config.Image}}'`.
  `exec` into a stopped container fails (rc 1), into a missing one too.
* Volumes: named (`-v name:/path`, created on first use, `volume create`, `volume rm [-f]`, refused while any
  container of that scope, running or not, uses it), anonymous (`-v /path`), and binds (`-v /src:/dst`, `src`
  read in the engine's own filesystem for an inner container). `:ro` mounts refuse writes.
* Files: every container has its own layer; paths resolve through its mounts (to a volume, an anonymous volume,
  a bind into the engine, or the lab server's disk). A small shell (`sh -c` / `bash -c`, and an argv with no
  shell) runs `[ ]`/`test`, `cat`, `printf`, `echo`, `mkdir`, `mv`, `cp`, `rm`, `tar -x -C`, redirections and
  `;`/`&&`/`||` over those files, `NAME=value` (put in when a later command runs), a subshell `( ... )
  [N>file]` (its fds, `exit` and locks end with it), a whole script `{ ...; } N>file`, `exec N>file` /
  `N>>` / `N<` / `N<>`, `flock` (exclusive; `-u N` drops it; `-s` is not modelled), `grep` with a fixed
  pattern (a non-`-F` pattern with regex metacharacters is not modelled), `head -c N /dev/urandom | base64`
  (a fixed secret). `$(...)` runs its command and yields its output; if that command is not modelled, it
  stays in `unmodelled` and yields a fixed word. Anything else is listed in `unmodelled`.
* Elasticsearch: a container whose image names `elasticsearch` answers a curl run inside it (`exec <it>
  bash -c <script> curl <args>`, or a script piping into curl) from its `FakeCluster`, printing the body
  then `\\n<http code>`. The frozen node's cluster state lives on its data volume
  (`/usr/share/elasticsearch/data`): a node started on another volume finds that volume's state (a new volume:
  an empty cluster), and removing the volume discards it. For `boot_requests` curls after each start the node
  is not listening yet: curl exits 7 and prints `000`, as it does on a refused connection.
* Capture's side of the live lab (#1347 r6.4.3 settlements: capture drives the real `LabOps` too). A container
  with `extra["role_host"]` is a role host: `exec <it> ps ...` prints its `extra["ps"]`; `exec [-u U] <it>
  bash -lc <cmd>` (or `sh -c`) is a command the host runs, opaque here: it is recorded (`host-command`) and
  exits 0. `commit [--pause=...] <container> <tag>` makes an image (`images`, bytes unique to that commit;
  a `commit` event); `save <image>` prints the image's bytes (an image the rig never committed: empty);
  `image rm` forgets it. `run --entrypoint E` runs `E` with the command as its arguments, and `tar -c -C
  <dir> -f - .` prints a tar (sorted, mtime 0) of the files under `<dir>`. A live stub with
  `extra["serves"]` (`{path: payload}`) answers the GET script with that payload (a path it does not serve:
  HTTP 404, exit 1). `scratch_cluster(container)` gives an Elasticsearch-image container started on the lab
  server itself (outside any engine) the cluster it answers from.
* Opening files: `>` truncates (or creates), `>>` appends, `1<>` opens for writing without truncating (the
  bytes written replace the file's first bytes, the rest stays), as does `dd of=F conv=notrunc` (from stdin,
  at byte 0). Each write records its `mode` (`create`, `truncate`, `append`, `in-place`, `copy`, `rename`)
  and the file's `size` after it. `set -C` (noclobber) makes `>` onto an existing file fail; `if ...; then
  ...; [else ...;] fi` and `exit N` work as in sh.
* Stubs (`cmdb`, `threat-intel`, `change-mgmt`, `ticket-server`, `identity`): a `python3 -c <GET script>
  <path>` exec answers a canonical view of what the stub holds (its environment, the seed files its
  `*_SEED_PATH` named when it started, the CMDB overlays posted to it); a `python3 -c <overlay script>` exec
  with a JSON list of `{host, patch}` on stdin posts overlays.

What this rig answers is a model of docker, not a demand of the contract. A command it does not model is
listed in `unmodelled` (exit 127), and the rigs assert that list is empty: that is a GAP IN THE FAKE, to be
closed by a test repair (model the command), never a reason for the lab code to change how it does something
the design leaves open. The stub names are the playground's own services (`playground-v2/compose.yml`); a stub
read is recognised however the lab spells it (a python `-c` script with the path as its argument or a local
URL in it, or curl/wget of a local URL).

Faults: `fail` is a set of effects that fail when attempted (`node-start`, `stub-start`, `proxy-start`,
`marker-write`: a write into the engine's state volume of a JSON object carrying `dirty` or `variant`). The
call returns rc 125 with `injected: <effect> failed` and changes nothing.
`node-restart` (r6.4.4) refuses `docker start` of an EXISTING frozen node as docker does when a container will
not start (rc 1, `Error response from daemon: ...`); a new node (`docker run`) still starts.

What a test reads: `containers`, `events` (`node-start`, `proxy-start`, `service-stop`, `volume-rm`, `curl`,
`write`), `writes`, `read_file`, `files_in_volume`, `running()`, `calls`, `unmodelled`.
"""
from __future__ import annotations

import copy
import io
import json
import posixpath
import re
import shlex
import subprocess
import tarfile
from dataclasses import dataclass, field
from typing import Any, Callable

from _lab_fakes import InjectedStep
from _periphery_fakes import FakeDocker

STUBS = ("cmdb", "threat-intel", "change-mgmt", "ticket-server", "identity")
ES_DATA = "/usr/share/elasticsearch/data"
NO_SUCH = "Error response from daemon: No such container: {}"


@dataclass
class Container:
    id: int
    scope: str
    name: str
    image: str
    env: dict
    mounts: list            # (dst, kind, ref, ro): kind "store" (ref = store id) or "bind" (ref = (host, src))
    command: list
    argv: list
    state: str = "created"
    cluster: Any = None     # the FakeCluster an Elasticsearch container answers from
    boot_left: int = 0
    engine: bool = False
    extra: dict = field(default_factory=dict)


def _norm(path: str) -> str:
    return posixpath.normpath("/" + path.lstrip("/"))




class RigDocker(FakeDocker):
    def __init__(self, *, journal: Any, clock: Any, cluster: Any = None, live_cluster: Any = None,
                 boot_requests: int = 0, fail: set | None = None, scratch_cluster: Callable | None = None,
                 on_service_stop: Callable[[], Any] | None = None,
                 on_volume_rm: Callable[[], Any] | None = None) -> None:
        super().__init__()
        self.journal, self.clock = journal, clock
        self.cluster, self.live_cluster = cluster, live_cluster
        self.boot_requests, self.fail = boot_requests, set(fail or ())
        self.on_service_stop, self.on_volume_rm = on_service_stop, on_volume_rm
        self.containers: dict[tuple[str, str], Container] = {}
        self.removed: list[Container] = []
        self.volumes: dict[tuple[str, str], tuple] = {}
        self.stores: dict[tuple, dict] = {}
        self.events: list[dict] = []
        self.writes: list[dict] = []
        self._ids = self._vols = 0
        self._undo: list | None = None
        self.cluster_store: tuple | None = None
        self.es_data: dict[tuple, dict] = {}
        self.stub_state: dict[int, dict] = {}
        self.injected: list[str] = []      # the effects `fail` refused, in order
        self.inodes: dict[tuple, int] = {}  # (store, key) -> inode: a rewrite keeps it, `mv` onto it replaces it
        self._inode = 0
        self.scratch_cluster = scratch_cluster
        self.images: dict[tuple[str, str], bytes] = {}
        # The ENV of an image, as a test declares it: `build` is a no-op here, so a variable the lab bakes into an
        # image it builds is visible only through this map (a gap to fill by test repair, not a demand).
        self.image_env: dict[str, dict] = {}
        # The files of an image (`{absolute path: bytes}`, e.g. a clock shim the lab COPYs into an image it
        # builds), likewise declared by a test: a container reads them where its own layer has nothing.
        self.image_files: dict[str, dict] = {}
        # flock: the lock files the running exec holds; races armed on a lock record (see `race_record`)
        self._held: list[tuple] = []
        self.lock_races: dict[tuple, Callable[[], Any]] = {}
        self.guard_of: dict[tuple, frozenset] = {}     # lock record -> the flock files held when it was created
        self._deferred: list[Callable[[], Any]] = []
        self._read_outside: set = set()

    # -- setup a test does ---------------------------------------------------------------------------

    def volume(self, scope: str, name: str) -> dict:
        """The files of named volume `name` in `scope` (created if absent), `{relative path: bytes}`."""
        return self.stores[self._volume(scope, name)]

    def existing(self, scope: str, name: str, image: str, *, cluster: Any = None, env: dict | None = None,
                 mounts: list | None = None) -> Container:
        """A container deployed before the test began, running."""
        c = self._new(scope, name, image, env or {}, mounts or [], [], [])
        c.state, c.cluster = "running", cluster
        return c

    def race_record(self, c: Container, path: str, fn: Callable[[], Any]) -> None:
        """Arm another operator acting on the record at `path` (in container `c`), e.g. a clear and a retake.
        That operator takes the record's flock (the lock file held when the record was created) for what it
        does, and acts at the worst moment for the holder: `fn()` runs right before the first write or delete of
        the record made WITHOUT holding that flock (after any read the holder already made); and if the holder
        read or tested the record outside that flock, `fn()` runs as soon as the holder takes the flock (it was
        waiting for it), so a decision made on that read is made on a stale record. Otherwise a write or delete
        inside the flock is never interleaved; then, as when nothing is written, `fn()` runs after the docker call
        ends. A release that compares and deletes inside the same flock as the take therefore cannot remove a
        record taken in between; a release that reads and then deletes outside it can."""
        store, key, _ro = self.resolve(c, path)
        self.lock_races[(store, key)] = fn

    def _saw(self, store, key) -> None:
        if (store, key) in self.lock_races and not (self.guard_of.get((store, key), frozenset()) & set(self._held)):
            self._read_outside.add((store, key))

    def _acquired(self) -> None:
        """A flock was just taken. The other operator, waiting on that flock, went first if the holder had
        already looked at the armed record outside it: what the holder read there may be stale now."""
        held = set(self._held)
        for rec in [r for r in self.lock_races if r in self._read_outside and self.guard_of.get(r, frozenset()) & held]:
            self.lock_races.pop(rec)()

    def _touch(self, c: Container, path: str) -> None:
        store, key, _ro = self.resolve(c, path)
        fn = self.lock_races.get((store, key))
        if fn is None:
            return
        del self.lock_races[(store, key)]
        if (store, key) not in self._read_outside and self.guard_of.get((store, key), frozenset()) & set(self._held):
            self._deferred.append(fn)
        else:
            fn()

    def stop_engine(self, scope: str, name: str) -> None:
        """The lab server rebooted, or someone ran `docker stop` on the engine: it and all it runs stop."""
        self._set_state(self.containers[(scope, name)], "exited")

    # -- what a test reads ---------------------------------------------------------------------------

    def running(self) -> set[tuple[str, str]]:
        return {k for k, c in self.containers.items() if c.state == "running"}

    def of_kind(self, kind: str) -> list[dict]:
        return [e for e in self.events if e["kind"] == kind]

    def resolve(self, c: Container, path: str) -> tuple[tuple, str, bool]:
        """(store id, key in that store, read-only) of `path` as container `c` sees it."""
        path = _norm(path)
        best = None
        for dst, kind, ref, ro in c.mounts:
            if (path == dst or path.startswith(dst.rstrip("/") + "/")) and (best is None or len(dst) > len(best[0])):
                best = (dst, kind, ref, ro)
        if best is None:
            return ("fs", c.id), path, False
        dst, kind, ref, ro = best
        rel = path[len(dst):].lstrip("/")
        if kind == "store":
            return ref, rel, ro
        host, src = ref
        target = _norm(src + ("/" + rel if rel else ""))
        if isinstance(host, tuple) and host[0] == "engine":
            engine = self.containers.get((host[1], host[2]))
            if engine is None:
                return ("gone",), target, True
            store, key, ro2 = self.resolve(engine, target)
            return store, key, ro or ro2
        return ("host", host), target, ro

    def read_file(self, c: Container, path: str) -> bytes | None:
        store, key, _ro = self.resolve(c, path)
        self._saw(store, key)
        found = self.stores.get(store, {}).get(key)
        if found is None and store == ("fs", c.id):       # not in the container's layer: its image's own file
            found = self.image_files.get(c.image, {}).get(key)
        return found

    def node(self) -> Container | None:
        """The frozen node container that exists now (any state), or None."""
        found = [c for c in self.containers.values() if c.cluster is self.cluster and "/" in c.scope]
        return found[-1] if found else None

    def services(self) -> list[Container]:
        """Containers the lab started that serve a frozen run: every container started in an engine's
        scope except the node, and any container running the product's proxy program."""
        return [c for c in self.containers.values()
                if c.extra.get("service") and c.state == "running"]

    # -- the CLI -------------------------------------------------------------------------------------

    def __call__(self, argv, **kw):
        argv = [str(a) for a in argv]
        self.calls.append((list(argv), dict(kw)))
        data = kw.get("input")
        stdin = data.encode() if isinstance(data, str) else (data or b"")
        self._undo = []
        rc, out, err = self._docker(argv, None, stdin)
        self._undo = None
        self._held = []
        deferred, self._deferred = self._deferred, []
        for fn in deferred:
            fn()
        text = kw.get("text") or kw.get("universal_newlines")
        out_v = out.decode(errors="replace") if text and isinstance(out, bytes) else out
        if not text and isinstance(out_v, str):
            out_v = out_v.encode()
        if text and isinstance(err, bytes):
            err = err.decode(errors="replace")
        if kw.get("stdout") not in (None, subprocess.PIPE) and hasattr(kw["stdout"], "write"):
            kw["stdout"].write(out if isinstance(out, bytes) else out.encode())
            out_v = None
        done = subprocess.CompletedProcess(argv, rc, stdout=out_v, stderr=err)
        if rc and kw.get("check"):
            raise subprocess.CalledProcessError(rc, argv, output=out_v, stderr=err)
        return done

    def _docker(self, argv: list[str], scope: str | None, stdin: bytes):
        assert argv and argv[0] == "docker", argv
        i, context = 1, None
        while i < len(argv) and argv[i].startswith("-"):
            if argv[i] in ("--context", "-c"):
                context = argv[i + 1]
                i += 2
            elif argv[i] in ("-H", "--host", "--config", "-l", "--log-level"):
                i += 2
            else:
                i += 1
        if scope is None:
            scope = context or "deploy"
        verb, rest = (argv[i], argv[i + 1:]) if i < len(argv) else ("", [])
        target = next((a for a in rest if not a.startswith("-")), "")
        self.journal.append(("docker", (scope, verb, target)))
        if "/" in scope and not self._daemon_up(scope):
            return 1, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
        if verb in ("run", "create"):
            return self._run(verb, rest, scope, stdin)
        if verb in ("start", "restart", "stop", "kill"):
            return self._lifecycle(verb, [a for a in rest if not a.startswith("-")], scope)
        if verb == "rm":
            return self._rm(rest, scope)
        if verb == "exec":
            return self._exec(rest, scope, stdin)
        if verb == "inspect":
            return self._inspect(rest, scope)
        if verb == "volume":
            return self._volume_cmd(rest, scope)
        if verb in ("network", "build", "version", "load", "pull", "tag"):
            return 0, "", ""
        if verb == "commit":
            return self._commit(rest, scope)
        if verb == "image":
            if rest and rest[0] == "rm":
                for tag in [a for a in rest[1:] if not a.startswith("-")]:
                    self.images.pop((scope, tag), None)
            return (0, "", "") if rest and rest[0] in ("inspect", "rm", "ls", "prune", "tag") else self._unmodelled(argv)
        if verb == "save":
            names = [a for a in rest if not a.startswith("-")]
            if any(a in ("-o", "--output") or a.startswith("--output=") for a in rest) or len(names) != 1:
                return self._unmodelled(argv)
            return 0, self.images.get((scope, names[0]), b""), ""
        return self._unmodelled(argv)

    def _unmodelled(self, argv):
        self.unmodelled.append(" ".join(map(str, argv)))
        return 127, b"", b"unmodelled by the rig docker"

    def _commit(self, rest: list[str], scope: str):
        names = [a for a in rest if not a.startswith("-")]
        if not names or len(names) > 2:
            return self._unmodelled(["docker", "commit", *rest])
        c = self.containers.get((scope, names[0]))
        if c is None:
            return 1, "", NO_SUCH.format(names[0])
        self._ids += 1
        tag = names[1] if len(names) == 2 else f"sha256:{self._ids:064x}"
        data = f"<image committed from {scope}/{c.name}, commit #{self._ids}>".encode()
        self.images[(scope, tag)] = data
        paused = not any(a in ("--pause=false", "-p=false", "--pause=0") for a in rest)
        self.events.append({"kind": "commit", "j": len(self.journal) - 1, "clock": self.clock.last, "container": c,
                            "tag": tag, "image": data, "paused": paused, "running": c.state == "running"})
        return 0, f"sha256:{self._ids:064x}\n", ""

    def _daemon_up(self, scope: str) -> bool:
        outer, name = scope.rsplit("/", 1)
        c = self.containers.get((outer, name))
        return c is not None and c.engine and c.state == "running"

    # -- containers ----------------------------------------------------------------------------------

    def _new(self, scope, name, image, env, mounts, command, argv) -> Container:
        self._ids += 1
        c = Container(self._ids, scope, name, image, dict(env), list(mounts), list(command), list(argv))
        self.containers[(scope, name)] = c
        self.stores[("fs", c.id)] = {}
        return c

    def _volume(self, scope: str, name: str) -> tuple:
        if (scope, name) not in self.volumes:
            self._vols += 1
            sid = ("vol", scope, name, self._vols)
            self.volumes[(scope, name)] = sid
            self.stores[sid] = {}
        return self.volumes[(scope, name)]

    def _host_of(self, scope: str):
        if "/" in scope:
            outer, name = scope.rsplit("/", 1)
            return ("engine", outer, name)
        return scope

    def _parse_run(self, rest: list[str]):
        opts = {"name": None, "detach": False, "rm": False, "env": [], "env_files": [], "volumes": [],
                "volumes_from": [], "add_hosts": [], "privileged": False, "entrypoint": None}
        values = {"--name": "name", "-e": "env", "--env": "env", "-v": "volumes", "--volume": "volumes",
                  "--env-file": "env_files", "--volumes-from": "volumes_from", "--add-host": "add_hosts",
                  "--entrypoint": "entrypoint"}
        skip = {"-p", "--publish", "--network", "--net", "-w", "--workdir", "-u", "--user", "--hostname", "-h",
                "-l", "--label", "--restart", "-m", "--memory", "--cpus", "--ip", "--dns", "--mount",
                "--log-driver", "--pid", "--cap-add", "--cap-drop", "--security-opt", "--ulimit", "--tmpfs",
                "--device", "--group-add", "--platform", "--pull", "--health-cmd", "--network-alias",
                "--shm-size", "--stop-timeout"}
        j = 0
        while j < len(rest) and rest[j].startswith("-"):
            opt = rest[j]
            if "=" in opt and opt.split("=", 1)[0] in values:
                key, val = opt.split("=", 1)
                k = values[key]
                opts[k] = val if k in ("name", "entrypoint") else opts[k] + [val]
            elif opt in values:
                k = values[opt]
                opts[k] = rest[j + 1] if k in ("name", "entrypoint") else opts[k] + [rest[j + 1]]
                j += 1
            elif opt in skip:
                j += 1
            elif opt in ("-d", "--detach"):
                opts["detach"] = True
            elif opt == "--rm":
                opts["rm"] = True
            elif opt == "--privileged":
                opts["privileged"] = True
            elif opt in ("-i", "-t", "-it", "--interactive", "--tty", "--init", "--read-only"):
                pass
            elif "=" in opt:
                pass
            else:
                self.unmodelled.append(f"run option {opt}")
            j += 1
        image, command = (rest[j], rest[j + 1:]) if j < len(rest) else ("", [])
        if opts["entrypoint"]:
            command = [opts["entrypoint"], *command]
        return opts, image, command

    def _run(self, verb: str, rest: list[str], scope: str, stdin: bytes):
        opts, image, command = self._parse_run(rest)
        name = opts["name"]
        if name is None:
            self._ids += 0
            name = f"anon{self._ids + 1:04d}"
        if (scope, name) in self.containers:
            return 125, "", f'docker: Error response from daemon: Conflict. The container name "/{name}" is already in use'
        kind = self._kind_of_start(scope, image, command, opts, name)
        if kind and kind in self.fail and (verb == "create" or opts["detach"]):
            self.injected.append(kind)
            return 125, "", f"injected: {kind} failed"
        env: dict = {}
        host = self._host_of(scope)
        for f in opts["env_files"]:
            data = self._read_host(scope, f)
            if data is None:
                return 125, "", f"docker: open {f}: no such file or directory"
            for line in data.decode().splitlines():
                if line.strip() and not line.lstrip().startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v
        for e in opts["env"]:
            k, _, v = e.partition("=")
            env[k] = v
        mounts = []
        for spec in opts["volumes_from"]:
            src_name, _, mode = spec.partition(":")
            src = self.containers.get((scope, src_name))
            if src is None:
                return 125, "", f"docker: Error response from daemon: No such container: {src_name}"
            mounts += [(d, k, r, ro or mode == "ro") for d, k, r, ro in src.mounts]
        anon = []
        for spec in opts["volumes"]:
            parts = spec.split(":")
            ro = len(parts) > 2 and "ro" in parts[2].split(",")
            if len(parts) == 1:
                self._vols += 1
                sid = ("anon", scope, self._vols)
                self.stores[sid] = {}
                anon.append(sid)
                mounts.append((_norm(parts[0]), "store", sid, False))
            elif parts[0].startswith("/"):
                mounts.append((_norm(parts[1]), "bind", (host, _norm(parts[0])), ro))
            else:
                mounts.append((_norm(parts[1]), "store", self._volume(scope, parts[0]), ro))
        c = self._new(scope, name, image, env, mounts, command, ["docker", "run", *rest])
        c.extra["anon"] = anon
        c.extra["add_hosts"] = list(opts["add_hosts"])
        c.engine = any("dockerd" in a for a in command)
        if "elasticsearch" in image and "/" in scope:
            c.cluster = self.cluster
        elif "elasticsearch" in image and self.scratch_cluster is not None:
            c.cluster = self.scratch_cluster(c)
        c.extra["service"] = kind in ("stub-start", "proxy-start", "service-start")
        if verb == "create":
            return 0, f"{c.id:064x}\n", ""
        if opts["detach"]:
            self._started(c, kind)
            return 0, f"{c.id:064x}\n", ""
        c.extra["image_files"] = True     # a fresh container reads its image's files (content unknown here)
        rc, out, err = self._shell_argv(c, command, stdin)
        c.extra["image_files"] = False
        c.state = "exited"
        if opts["rm"]:
            self._forget(c, volumes=True)
        return rc, out, err

    def _kind_of_start(self, scope, image, command, opts, name) -> str | None:
        joined = " ".join([image, *command, *opts["env"]])
        if "defender.credential_proxy" in joined:
            return "proxy-start"
        if "/" in scope and "elasticsearch" in image:
            return "node-start"
        if "/" in scope and name in STUBS:
            return "stub-start"
        if "/" in scope and opts["detach"]:
            return "service-start"
        return None

    def _started(self, c: Container, kind: str | None) -> None:
        c.state = "running"
        self.started.add((c.scope, c.name))
        if c.cluster is self.cluster and self.cluster is not None:
            self._node_started(c)
        if kind == "proxy-start":
            node = self.node()
            self.events.append({"kind": "proxy-start", "j": len(self.journal) - 1, "clock": self.clock.last,
                                "container": c, "node": node,
                                "node_running": node is not None and node.state == "running"})
        if c.name in STUBS and "/" in c.scope:
            seeds = {}
            for k, v in sorted(c.env.items()):
                if k.endswith("_SEED_PATH"):
                    data = self.read_file(c, v)
                    seeds[k] = None if data is None else data.decode(errors="replace")
            self.stub_state[c.id] = {"seeds": seeds, "overlays": {}}
            self.events.append({"kind": "stub-start", "j": len(self.journal) - 1, "clock": self.clock.last,
                                "container": c})

    def _node_started(self, c: Container) -> None:
        store = self.resolve(c, ES_DATA)[0]
        if store != self.cluster_store:
            if self.cluster_store is not None and self.cluster_store in self.stores:
                self.es_data[self.cluster_store] = self.cluster.save_node_state()
            self.cluster.load_node_state(self.es_data.pop(store, None))
            self.cluster_store = store
        c.boot_left = self.boot_requests
        offset_file = c.env.get("V2_CLOCK_OFFSET_FILE")
        raw = self.read_file(c, offset_file) if offset_file else None
        where = self.resolve(c, offset_file) if offset_file else None
        inode = self.inodes.get((where[0], where[1])) if where else None
        preload = c.env.get("LD_PRELOAD") or self.image_env.get(c.image, {}).get("LD_PRELOAD")
        self.events.append({"kind": "node-start", "j": len(self.journal) - 1, "clock": self.clock.last,
                            "container": c, "data": store, "offset_file": offset_file,
                            "offset": raw.decode(errors="replace") if raw is not None else None,
                            "inode": inode, "preload": preload,
                            "preload_found": bool(preload) and all(
                                self.read_file(c, p) is not None for p in re.split(r"[\s:]+", preload) if p)})

    def _set_state(self, c: Container, state: str) -> None:
        was = c.state
        c.state = state
        if was == "running" and state != "running":
            if c.extra.get("service") and self.on_service_stop:
                self.events.append({"kind": "service-stop", "j": len(self.journal) - 1, "clock": self.clock.last,
                                    "container": c, "seen": self.on_service_stop()})
            if c.engine:
                for (scope, _n), inner in list(self.containers.items()):
                    if scope == f"{c.scope}/{c.name}" and inner.state == "running":
                        self._set_state(inner, "exited")

    def _lifecycle(self, verb: str, names: list[str], scope: str):
        for name in names:
            c = self.containers.get((scope, name))
            if c is None:
                return 1, "", NO_SUCH.format(name)
            if verb in ("start", "restart"):
                kind = "node-start" if c.cluster is self.cluster and "/" in scope else None
                if kind and kind in self.fail:
                    self.injected.append(kind)
                    return 125, "", f"injected: {kind} failed"
                if kind and "node-restart" in self.fail:       # r6.4.4: an existing node that will not start again
                    self.injected.append("node-restart")
                    return 1, "", (f"Error response from daemon: failed to create task for container: {name}\n"
                                   f"Error: failed to start containers: {name}")
                if verb == "restart" and c.state == "running":
                    self._set_state(c, "exited")
                if c.state != "running":
                    self._started(c, kind)
            else:
                self._set_state(c, "exited")
        return 0, "\n".join(names) + "\n", ""

    def _forget(self, c: Container, *, volumes: bool) -> None:
        self.events.append({"kind": "container-rm", "j": len(self.journal) - 1, "clock": self.clock.last,
                            "container": c})
        self.containers.pop((c.scope, c.name), None)
        self.removed.append(c)
        for sid in [("fs", c.id), *(c.extra.get("anon", []) if volumes else [])]:
            self._drop_store(sid)

    def _drop_store(self, sid: tuple) -> None:
        if sid in self.stores:
            self.events.append({"kind": "store-drop", "j": len(self.journal) - 1, "clock": self.clock.last,
                                "store": sid})
        self.stores.pop(sid, None)
        if sid == self.cluster_store:
            self.cluster.load_node_state(None)
            self.cluster_store = None
        self.es_data.pop(sid, None)

    def _rm(self, rest: list[str], scope: str):
        force = any(a in ("-f", "--force") or (a.startswith("-") and not a.startswith("--") and "f" in a) for a in rest)
        vols = any(a in ("-v", "--volumes") or (a.startswith("-") and not a.startswith("--") and "v" in a) for a in rest)
        for name in [a for a in rest if not a.startswith("-")]:
            c = self.containers.get((scope, name))
            if c is None:
                if force:
                    continue
                return 1, "", NO_SUCH.format(name)
            if c.state == "running" and not force:
                return 1, "", f'Error response from daemon: cannot remove container "/{name}": container is running'
            if c.state == "running":
                self._set_state(c, "exited")
            self._forget(c, volumes=vols)
        return 0, "", ""

    def _volume_cmd(self, rest: list[str], scope: str):
        if not rest:
            return self._unmodelled(["docker", "volume"])
        sub, args = rest[0], rest[1:]
        names = [a for a in args if not a.startswith("-")]
        if sub == "create":
            for n in names:
                self._volume(scope, n)
            return 0, "\n".join(names) + "\n", ""
        if sub == "rm":
            force = any(a in ("-f", "--force") for a in args)
            for n in names:
                sid = self.volumes.get((scope, n))
                if sid is None:
                    if force:
                        continue
                    return 1, "", f"Error response from daemon: get {n}: no such volume"
                users = [c.name for c in self.containers.values() if c.scope == scope
                         and any(k == "store" and r == sid for _d, k, r, _ro in c.mounts)]
                if users:
                    return 1, "", f"Error response from daemon: remove {n}: volume is in use - [{', '.join(users)}]"
                self.events.append({"kind": "volume-rm", "j": len(self.journal) - 1, "clock": self.clock.last,
                                    "volume": sid, "seen": self.on_volume_rm() if self.on_volume_rm else None})
                del self.volumes[(scope, n)]
                self._drop_store(sid)
            return 0, "\n".join(names) + "\n", ""
        if sub in ("ls", "inspect"):
            if sub == "inspect":
                missing = [n for n in names if (scope, n) not in self.volumes]
                return (1, "", f"no such volume: {missing[0]}") if missing else (0, "[]\n", "")
            return 0, "".join(f"{n}\n" for (s, n) in self.volumes if s == scope), ""
        return self._unmodelled(["docker", "volume", *rest])

    def _inspect(self, rest: list[str], scope: str):
        fmt, names, j = None, [], 0
        while j < len(rest):
            if rest[j] in ("-f", "--format"):
                fmt, j = rest[j + 1], j + 2
                continue
            if rest[j].startswith("--format="):
                fmt = rest[j].split("=", 1)[1]
            elif rest[j].startswith("--type"):
                j += 1 if "=" in rest[j] else 2
                continue
            elif not rest[j].startswith("-"):
                names.append(rest[j])
            j += 1
        out = []
        for name in names:
            c = self.containers.get((scope, name))
            if c is None:
                return 1, "", f"Error: No such object: {name}"
            if fmt is None:
                out.append(json.dumps([{"Name": name, "State": {"Running": c.state == "running"},
                                        "Config": {"Image": c.image}}]))
            elif fmt.replace(" ", "") == "{{.State.Running}}":
                out.append("true" if c.state == "running" else "false")
            elif fmt.replace(" ", "") == "{{.Config.Image}}":
                out.append(c.image)
            elif fmt.replace(" ", "") == "{{.State.Status}}":
                out.append(c.state)
            else:
                return self._unmodelled(["docker", "inspect", "-f", fmt, name])
        return 0, "\n".join(out) + "\n", ""

    # -- exec ----------------------------------------------------------------------------------------

    def _exec(self, rest: list[str], scope: str, stdin: bytes):
        j, env, user = 0, {}, None
        while j < len(rest) and rest[j].startswith("-"):
            if rest[j] in ("-e", "--env"):
                k, _, v = rest[j + 1].partition("=")
                env[k] = v
                j += 2
            elif rest[j] in ("-u", "--user"):
                user, j = rest[j + 1], j + 2
            elif rest[j] in ("-w", "--workdir"):
                j += 2
            else:
                j += 1
        if j >= len(rest):
            return self._unmodelled(["docker", "exec", *rest])
        name, command = rest[j], rest[j + 1:]
        c = self.containers.get((scope, name))
        if c is None:
            if self.cluster is not None and "/" in scope and name == "elasticsearch":
                self.cluster.down_requests.append(" ".join(command)[-120:])
            return 1, "", NO_SUCH.format(name)
        if c.state != "running":
            if c.cluster is not None:
                c.cluster.down_requests.append(" ".join(command)[-120:])
            return 1, "", f"Error response from daemon: container {c.id:064x} is not running"
        if command and command[0] == "docker" and c.engine:
            return self._docker(command, f"{scope}/{name}", stdin)
        if c.cluster is not None and self._curl_args(command) is not None:
            return self._curl(c, self._curl_args(command), stdin)
        if c.name in STUBS and self._stub_request(command) is not None:
            return self._stub(c, command, stdin)
        if c.extra.get("role_host") and len(command) >= 3 and command[0].rsplit("/", 1)[-1] in ("bash", "sh") \
                and command[1] in ("-c", "-lc", "-cl"):
            self.events.append({"kind": "host-command", "j": len(self.journal) - 1, "clock": self.clock.last,
                                "container": c, "host": c.name, "user": user, "command": command[2]})
            return 0, "", ""
        return self._shell_argv(c, command, stdin, env)

    # -- Elasticsearch over curl ---------------------------------------------------------------------

    @staticmethod
    def _curl_args(command: list[str]) -> list[str] | None:
        if len(command) >= 3 and command[0].rsplit("/", 1)[-1] in ("sh", "bash") and command[1] == "-c":
            extra = command[3:]
            if extra and extra[0] == "curl" and "curl" in command[2]:
                in_script = ["-w", "%{http_code}"] if re.search(r"(^|\s)(-w|--write-out)\s", command[2]) else []
                return in_script + extra[1:]
            if "curl " in command[2]:
                words = shlex.split(command[2].split("|")[-1])
                if words and words[0] == "curl":
                    return words[1:]
            return None
        if command and command[0] == "curl":
            return command[1:]
        return None

    def _curl(self, c: Container, args: list[str], stdin: bytes):
        method, body, url, write_out, fail = "GET", None, None, None, False
        j = 0
        while j < len(args):
            a = args[j]
            if a in ("-X", "--request"):
                method, j = args[j + 1], j + 1
            elif a in ("-H", "--header", "-K", "--config", "-u", "--user"):
                j += 1
            elif a in ("--data-binary", "-d", "--data", "--data-raw"):
                raw = args[j + 1]
                body = stdin.decode() if raw == "@-" else raw
                j += 1
                if method == "GET":
                    method = "POST"
            elif a in ("-w", "--write-out"):
                write_out, j = args[j + 1], j + 1
            elif a in ("-f", "--fail"):
                fail = True
            elif a.startswith("http://") or a.startswith("https://"):
                url = a
            j += 1
        if url is None:
            return self._unmodelled(["curl", *args])
        tail = "\n000" if write_out else ""
        if c.boot_left > 0:
            c.boot_left -= 1
            self.events.append({"kind": "curl-refused", "j": len(self.journal) - 1, "clock": self.clock.last,
                                "node": c.id})
            return 7, tail, "curl: (7) Failed to connect to localhost port 9200: Connection refused"
        path = "/" + url.split("://", 1)[1].split("/", 1)[1] if "/" in url.split("://", 1)[1] else "/"
        payload = json.loads(body) if body not in (None, "") else None
        if c.cluster is self.cluster:
            self.events.append({"kind": "curl", "j": len(self.journal) - 1, "clock": self.clock.last, "node": c.id,
                                "data": self.cluster_store, "method": method.upper(), "path": path,
                                "body": copy.deepcopy(payload),
                                "proxy_running": any(s.extra.get("proxy") or "defender.credential_proxy"
                                                     in " ".join(s.command) for s in self.services())})
        try:
            answer = c.cluster.es_request(method.upper(), path, payload)
            code = 200
        except InjectedStep:
            raise
        except AssertionError:
            raise
        except RuntimeError as exc:
            text = str(exc)
            code = 404 if ("not_found" in text or "missing" in text) else 400 if "exception" in text else 500
            answer = {"error": {"type": "exception", "reason": text}, "status": code}
        out = json.dumps(answer)
        if fail and code >= 400:
            return 22, "", f"curl: (22) The requested URL returned error: {code}"
        return 0, out + (f"\n{code}" if write_out else ""), ""

    # -- stubs ---------------------------------------------------------------------------------------

    _LOCAL_URL = re.compile(r"https?://(?:127\.0\.0\.1|localhost)(?::\d+)?(/[^\s'\"]*)")

    @classmethod
    def _stub_request(cls, command: list[str]):
        """(kind, path) of a stub request however it is spelled: a python `-c` script reading the path from its
        argument or naming a local URL, or curl/wget of a local URL; kind is "read" or "overlay" (the overlay
        post: a script naming `/admin/overlay/` with no argument). None: not a stub request this rig knows."""
        if len(command) >= 3 and command[0].rsplit("/", 1)[-1] in ("python", "python3") and command[1] == "-c":
            script, args = command[2], command[3:]
            if "/admin/overlay/" in script and not args:
                return "overlay", None
            if args and args[0].startswith("/"):
                return "read", args[0]
            m = cls._LOCAL_URL.search(script)
            return ("read", m.group(1)) if m else None
        if command and command[0].rsplit("/", 1)[-1] in ("curl", "wget"):
            if any(a in ("-d", "--data", "--data-binary", "--data-raw", "--post-data", "--post-file", "-X", "--request",
                         "-T", "--upload-file", "-F", "--form") or a.startswith(("--data", "--post", "-X")) for a in command[1:]):
                return None       # a write to the stub (or another method): not a read; unmodelled
            for a in command[1:]:
                m = cls._LOCAL_URL.fullmatch(a)
                if m:
                    return "read", m.group(1)
        return None

    def _stub(self, c: Container, command: list[str], stdin: bytes):
        request = self._stub_request(command)
        if request is None:
            return self._unmodelled(["docker", "exec", c.name, *[a[:60] for a in command]])
        kind, path = request
        serves = c.extra.get("serves")
        if serves is not None and kind == "read":
            if path not in serves:
                return 1, "", "HTTP Error 404: Not Found"
            return 0, json.dumps(serves[path]), ""
        state = self.stub_state.setdefault(c.id, {"seeds": {}, "overlays": {}})
        if kind == "overlay":
            try:
                items = json.loads(stdin.decode() or "[]")
            except ValueError:
                return 1, "", "bad overlay input"
            for item in items:
                state["overlays"].setdefault(item["host"], {}).update(copy.deepcopy(item["patch"]))
            return 0, "", ""
        view = {"stub": c.name, "path": path, "env": dict(sorted(c.env.items())),
                "seeds": state["seeds"], "overlays": state["overlays"]}
        return 0, json.dumps(view, sort_keys=True), ""

    # -- files and the small shell -------------------------------------------------------------------

    def _read_host(self, scope: str, path: str) -> bytes | None:
        if "/" in scope:
            outer, name = scope.rsplit("/", 1)
            engine = self.containers.get((outer, name))
            return None if engine is None else self.read_file(engine, path)
        return self.stores.get(("host", scope), {}).get(_norm(path))

    def _write(self, c: Container, path: str, data: bytes, mode: str = "truncate") -> str | None:
        """`mode`: `truncate` (`>`), `append` (`>>`, `data` is what is added), `in-place` (`1<>`, dd
        conv=notrunc: `data` replaces the first bytes), `copy`, `rename`. A file that did not exist is `create`."""
        store, key, ro = self.resolve(c, path)
        if ro or store == ("gone",):
            return f"{path}: Read-only file system"
        self._touch(c, path)
        files = self.stores.setdefault(store, {})
        prior = files.get(key)
        if prior is None:
            self.guard_of[(store, key)] = frozenset(self._held)
        self._undo.append((store, key, prior))
        if key not in files or (store, key) not in self.inodes:
            self._inode += 1
            self.inodes[(store, key)] = self._inode
        if mode == "append":
            files[key] = (prior or b"") + data
        elif mode == "in-place":
            files[key] = data + (prior or b"")[len(data):]
        else:
            files[key] = data
        entry = {"kind": "write", "j": len(self.journal) - 1, "clock": self.clock.last, "store": store, "key": key,
                 "data": data, "container": c, "inode": self.inodes[(store, key)],
                 "mode": "create" if prior is None and mode not in ("rename", "copy") else mode,
                 "size": len(files[key])}
        self.writes.append(entry)
        return None

    def _remove(self, c: Container, path: str, recursive: bool) -> None:
        self._touch(c, path)
        store, key, _ro = self.resolve(c, path)
        files = self.stores.get(store, {})
        for k in [k for k in files if k == key or (recursive and k.startswith(key.rstrip("/") + "/"))]:
            self._undo.append((store, k, files[k]))
            del files[k]
            self.inodes.pop((store, k), None)

    def _exists(self, c: Container, path: str, kind: str) -> bool:
        store, key, _ro = self.resolve(c, path)
        self._saw(store, key)
        files = self.stores.get(store, {})
        is_file = key in files
        is_dir = any(k.startswith(key.rstrip("/") + "/") for k in files) or any(
            dst == _norm(path) for dst, *_ in c.mounts)
        return {"-f": is_file, "-e": is_file or is_dir, "-d": is_dir, "-s": is_file and bool(files.get(key))}[kind]

    def _shell_argv(self, c: Container, command: list[str], stdin: bytes, env: dict | None = None):
        if not command:
            return 0, "", ""
        if len(command) >= 3 and command[0].rsplit("/", 1)[-1] in ("sh", "bash") and command[1] == "-c":
            positional = command[3:]
            return self._shell(c, command[2], stdin, {**c.env, **(env or {})}, positional)
        return self._commands(c, [("", list(command), [])], stdin, {**c.env, **(env or {})})

    def _shell(self, c: Container, script: str, stdin: bytes, env: dict, positional: list[str]):
        subs: dict[str, str] = {}
        if _RANDOM_TOKEN.fullmatch(script):
            # `head -c N /dev/urandom | base64 [| tr -d ...]`: a secret drawn from the kernel; any fixed word does
            return 0, b"rigsecretrigsecretrigsecretrigsecret\n", b""
        grouped = _groups(script)
        if grouped is None:
            return self._unmodelled(["sh", "-c", script])
        script, groups = grouped
        script = _premark(script, subs).replace("\n", ";")
        lex = shlex.shlex(script, posix=True, punctuation_chars=";&|<>")
        lex.whitespace_split, lex.commenters = True, ""
        try:
            tokens = list(lex)
        except ValueError:
            return self._unmodelled(["sh", "-c", script])
        names = {"0": positional[0] if positional else "sh",
                 **{str(i): v for i, v in enumerate(positional[1:], 1)}, **env}

        def expand(word: str) -> str:      # variables are put in when the command runs (see `_simple`)
            return word

        commands, words, redirects, op = [], [], [], ""
        k = 0
        while k < len(tokens):
            t = tokens[k]
            if t in (";", "&&", "||", "|", "&", ";;"):
                if t in ("|", "&"):
                    return self._unmodelled(["sh", "-c", script])
                if words or redirects:
                    commands.append((op, words, redirects))
                words, redirects, op = [], [], t
            elif t in (">", ">>", "<", ">|", "<>", "1<>"):
                if k + 1 >= len(tokens):
                    return self._unmodelled(["sh", "-c", script])
                target = expand(tokens[k + 1])
                if words and words[-1] == "2" and t in (">", ">>"):
                    words.pop()
                    redirects.append(("2>", target))
                elif t == "<>" and words and words[-1] == "1":
                    words.pop()
                    redirects.append(("1<>", target))
                elif t == "<>" and words and words[-1].isdigit():
                    redirects.append(("<>", target))
                elif t == "<>":
                    return self._unmodelled(["sh", "-c", script])
                else:
                    if words and words[-1] == "1" and t in (">", ">>", ">|"):
                        words.pop()
                    redirects.append((t, target))
                k += 1
            else:
                words.append(expand(t))
            k += 1
        if words or redirects:
            commands.append((op, words, redirects))
        return self._commands(c, commands, stdin, env, {"subs": subs, "positional": positional, "vars": names,
                                                        "groups": groups})

    def _commands(self, c: Container, commands: list, stdin: bytes, env: dict, ctx: dict | None = None):
        writes_before = len(self.writes)
        held_before = len(self._held)
        st = {"noclobber": False, "rc": 0, "out": b"", "err": b"", "fds": {},
              **(ctx or {"subs": {}, "positional": [], "vars": dict(env), "groups": {}})}
        try:
            return self._commands_in(c, commands, stdin, env, st, writes_before)
        finally:
            del self._held[held_before:]          # a flock taken on an fd lasts until its shell ends

    def _commands_in(self, c: Container, commands: list, stdin: bytes, env: dict, st: dict, writes_before: int):
        try:
            nodes, _end = self._block(commands, 0, ())
        except _Syntax:
            return self._unmodelled(["sh", "-c", " ; ".join(" ".join(w) for _o, w, _r in commands)])
        try:
            rc = self._nodes(c, nodes, stdin, env, st)
        except _Exit as done:
            rc = done.rc
        out, err = st["out"], st["err"]
        failed = self._injected_marker_write(writes_before)
        if failed:
            for store, key, prior in reversed(self._undo or []):
                files = self.stores.setdefault(store, {})
                if prior is None:
                    files.pop(key, None)
                else:
                    files[key] = prior
            del self.writes[writes_before:]
            self.injected.append(failed)
            return 125, b"", f"injected: {failed} failed".encode()
        return rc, out, err

    def _block(self, cmds: list, i: int, stops: tuple):
        """`cmds[i:]` as nodes up to a command whose first word is in `stops`: ("cmd", op, words, redirects)
        or ("if", op, condition, then, else)."""
        nodes = []
        while i < len(cmds):
            op, words, redirects = cmds[i]
            if words and words[0] in stops:
                return nodes, i
            if words and words[0] in ("then", "else", "elif", "fi", "while", "for", "until", "do", "done", "case"):
                raise _Syntax(words[0])
            if words and words[0] == "if":
                cond, k = self._block([("", words[1:], redirects), *cmds[i + 1:]], 0, ("then",))
                j = i + k
                if j >= len(cmds):
                    raise _Syntax("if")
                then, k = self._block([("", cmds[j][1][1:], cmds[j][2]), *cmds[j + 1:]], 0, ("else", "elif", "fi"))
                j += k
                if j >= len(cmds) or cmds[j][1][0] == "elif":
                    raise _Syntax("then")
                orelse = []
                if cmds[j][1][0] == "else":
                    orelse, k = self._block([("", cmds[j][1][1:], cmds[j][2]), *cmds[j + 1:]], 0, ("fi",))
                    j += k
                    if j >= len(cmds):
                        raise _Syntax("else")
                if cmds[j][1][1:] or cmds[j][2]:
                    raise _Syntax("fi")
                nodes.append(("if", op, cond, then, orelse))
                i = j + 1
                continue
            if words or redirects:
                nodes.append(("cmd", op, words, redirects))
            i += 1
        if stops:
            raise _Syntax("unterminated")
        return nodes, i

    def _nodes(self, c: Container, nodes: list, stdin: bytes, env: dict, st: dict) -> int:
        rc = st["rc"]
        for node in nodes:
            op = node[1]
            if (op == "&&" and rc != 0) or (op == "||" and rc == 0):
                continue
            if node[0] == "if":
                branch = node[3] if self._nodes(c, node[2], stdin, env, st) == 0 else node[4]
                rc = self._nodes(c, branch, stdin, env, st) if branch else 0
            else:
                rc = self._simple(c, node[2], node[3], stdin, env, st)
            st["rc"] = rc
        return rc

    def _substitute(self, c: Container, word: str, env: dict, st: dict) -> str:
        """`$(...)` run when its command runs (in a subshell of this one: the variables set so far are seen). A
        substitution whose command this shell cannot run stays in `unmodelled` (a gap) and yields a fixed word."""
        for key, inner in st["subs"].items():
            if key in word:
                before = len(self.unmodelled)
                _rc, o, _e = self._shell(c, inner, b"", {**env, **st["vars"]}, st["positional"])
                if len(self.unmodelled) > before:
                    value = "substituted"
                else:
                    value = (o.decode(errors="replace") if isinstance(o, bytes) else o).rstrip("\n")
                word = word.replace(key, value)
        return word

    def _flock(self, c: Container, words: list, stdin: bytes, env: dict, st: dict) -> int:
        """`flock [-x|-s|-n|-w N] <file> <command...>` / `flock <file> -c <script>`: the command runs holding
        the lock file; `flock [-x] <fd>` holds the file `exec <fd>>file` opened until the shell ends."""
        args, j = words[1:], 0
        while j < len(args) and args[j].startswith("-") and args[j] != "-c":
            j += 2 if args[j] in ("-w", "--timeout", "-E", "--conflict-exit-code") else 1
        if j >= len(args):
            self._unmodelled(words)
            return 127
        target, rest = args[j], args[j + 1:]
        if any(a in ("-s", "--shared") for a in args[:j]):
            self._unmodelled(words)      # a shared lock guards nothing against another taker: not modelled
            return 127
        if target.isdigit() and ("-u" in args[:j] or "--unlock" in args[:j]):
            where = self.resolve(c, st["fds"].get(target, ""))[:2] if target in st["fds"] else None
            if where in self._held:
                self._held.remove(where)
            return 0
        if target.isdigit():
            if rest or target not in st["fds"]:
                self._unmodelled(words)
                return 127
            self._held.append(self.resolve(c, st["fds"][target])[:2])
            self._acquired()
            return 0
        if any(a in ("-u", "--unlock") for a in args[:j]):
            self._unmodelled(words)
            return 127
        if self.read_file(c, target) is None:
            self._write(c, target, b"", "append")
        self._held.append(self.resolve(c, target)[:2])
        self._acquired()
        try:
            if rest[:1] == ["-c"] and len(rest) == 2:
                rc, o, e = self._shell(c, rest[1], stdin, env, [])
            elif rest:
                rc, o, e = self._shell_argv(c, rest, stdin, env)
            else:
                self._unmodelled(words)
                return 127
        finally:
            self._held.pop()
        st["out"] += o if isinstance(o, bytes) else o.encode()
        st["err"] += e if isinstance(e, bytes) else e.encode()
        return rc

    def _simple(self, c: Container, words: list, redirects: list, stdin: bytes, env: dict, st: dict) -> int:
        def put_in(word: str) -> str:
            word = _VARMARK.sub(lambda m: st["vars"].get(m.group(1), ""), word)
            return self._substitute(c, word, env, st) if st["subs"] else word
        words = [put_in(w) for w in words]
        redirects = [(k, put_in(t)) for k, t in redirects]
        if len(words) == 1 and not redirects and re.fullmatch(r"[A-Za-z_]\w*=.*", words[0], re.S):
            name, _, value = words[0].partition("=")
            st["vars"][name] = value
            return 0
        if words and words[0] == _GROUP_WORD:
            # `( body ) [N>file]`: body in a subshell (its `exit`, its variables and its fds end with it), with
            # fd N open on file while it runs; a lock taken on that fd is released when the subshell ends
            kind, body = st["groups"][words[1]]
            fd = words[2:]
            if len(fd) > 1 or (fd and not (fd[0].isdigit() and len(redirects) == 1)) or (redirects and not fd):
                self._unmodelled(words)
                return 127
            if fd:
                op, path = redirects[0]
                body = f"exec {fd[0]}{op}{shlex.quote(path)}; {body}"
            rc, o, e = self._shell(c, body, stdin, {**env, **st["vars"]}, st["positional"])
            st["out"] += o if isinstance(o, bytes) else o.encode()
            st["err"] += e if isinstance(e, bytes) else e.encode()
            return rc
        if words and words[0] == "exec":
            kinds = [k for k, _t in redirects]
            if len(words) == 2 and words[1].isdigit() and kinds in ([">"], [">>"], ["<"], ["<>"]):
                path = redirects[0][1]
                if self.read_file(c, path) is None:
                    if kinds == ["<"]:
                        st["err"] += f"sh: can't open {path}: no such file\n".encode()
                        return 2
                    self._write(c, path, b"", "append")
                st["fds"][words[1]] = path
                return 0
            self._unmodelled(words)
            return 127
        if any(k == "<>" for k, _t in redirects):
            self._unmodelled(words)
            return 127
        if words and words[0] == "flock":
            return self._flock(c, words, stdin, env, st)
        if words and words[0] == "exit":
            raise _Exit(int(words[1]) if len(words) > 1 else st["rc"])
        if words[:2] == ["set", "-C"] or words[:3] == ["set", "-o", "noclobber"]:
            st["noclobber"] = True
            return 0
        quiet = any(kind == "2>" for kind, _t in redirects)
        data_in = stdin
        for kind, target in redirects:
            if kind == "<":
                data_in = self.read_file(c, target) or b""
            if kind == ">" and st["noclobber"] and target != "/dev/null" and self._exists(c, target, "-e"):
                if not quiet:
                    st["err"] += f"sh: can't create {target}: File exists\n".encode()
                return 1
        rc, o, e = self._command(c, words, data_in)
        for kind, target in redirects:
            if kind in (">", ">>", ">|", "1<>"):
                if target != "/dev/null":
                    mode = {">>": "append", "1<>": "in-place"}.get(kind, "truncate")
                    problem = self._write(c, target, o, mode)
                    if problem:
                        rc, e = 1, problem.encode()
                o = b""
            if kind == "2>":
                e = b""
        st["out"] += o
        st["err"] += e
        return rc

    def _grep(self, c: Container, words: list[str], args: list[str], stdin: bytes):
        quiet = fixed = False
        pattern, files, j = None, [], 0
        while j < len(args):
            a = args[j]
            if a == "-e":
                pattern, j = args[j + 1], j + 2
                continue
            if a.startswith("-") and len(a) > 1 and pattern is None:
                if set(a[1:]) - set("qFs"):
                    return self._unmodelled(words)
                quiet, fixed = quiet or "q" in a, fixed or "F" in a
            elif pattern is None:
                pattern = a
            else:
                files.append(a)
            j += 1
        if pattern is None:
            return self._unmodelled(words)
        if not fixed and re.search(r"[.\[\]*^$\\+?(){}|]", pattern):
            return self._unmodelled(words)     # a basic regular expression: not modelled
        texts = []
        for f in files or [None]:
            data = stdin if f is None else self.read_file(c, f)
            if data is None:
                return 2, b"", f"grep: {f}: No such file or directory".encode()
            texts.append(data.decode(errors="replace"))
        rx = re.compile(re.escape(pattern))
        hits = [ln for t in texts for ln in t.splitlines() if rx.search(ln)]
        return (0 if hits else 1), (b"" if quiet else "".join(h + "\n" for h in hits).encode()), b""

    def _dd(self, c: Container, args: list[str], stdin: bytes):
        opts = dict(a.split("=", 1) for a in args if "=" in a)
        if set(opts) - {"of", "if", "conv", "bs", "count", "seek", "status", "oflag", "iflag"} or "of" not in opts \
                or opts.get("seek", "0") != "0" or opts.get("oflag") or opts.get("iflag"):
            return self._unmodelled(["dd", *args])
        data = stdin if "if" not in opts else self.read_file(c, opts["if"])
        if data is None:
            return 1, b"", f"dd: failed to open '{opts['if']}': No such file or directory".encode()
        if "count" in opts:
            data = data[:int(opts.get("bs", "512")) * int(opts["count"])]
        mode = "in-place" if "notrunc" in opts.get("conv", "").split(",") else "truncate"
        problem = self._write(c, opts["of"], data, mode)
        return (1, b"", problem.encode()) if problem else (0, b"", b"")

    def _tar_create(self, c: Container, args: list[str], words: list[str]):
        if "-C" not in args or args.index("-C") + 1 >= len(args):
            return self._unmodelled(words)
        top = args[args.index("-C") + 1]
        rest = [a for k, a in enumerate(args) if not a.startswith("-") and (k == 0 or args[k - 1] != "-C")]
        if rest != ["-", "."] and rest != ["."]:
            return self._unmodelled(words)
        if not ("f" in "".join(a for a in args if a.startswith("-") and a != "-C") and "-" in args):
            return self._unmodelled(words)
        store, key, _ro = self.resolve(c, top)
        files = self.stores.get(store, {})
        prefix = key.rstrip("/") + "/" if key else ""
        members = {"./" + k[len(prefix):]: v for k, v in files.items() if (not prefix or k.startswith(prefix))}
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for name, data in sorted(members.items()):
                info = tarfile.TarInfo(name)
                info.size, info.mtime = len(data), 0
                tar.addfile(info, io.BytesIO(data))
        return 0, buf.getvalue(), b""

    def _injected_marker_write(self, since: int) -> str | None:
        if "marker-write" not in self.fail:
            return None
        for w in self.writes[since:]:
            if w["store"][0] == "vol" and w["store"][2] == "lab-engine-state":
                try:
                    doc = json.loads(w["data"])
                except ValueError:
                    continue
                if isinstance(doc, dict) and ({"dirty", "variant"} & set(doc)):
                    return "marker-write"
        return None

    def _command(self, c: Container, words: list[str], stdin: bytes):
        if not words:
            return 0, b"", b""
        cmd, args = words[0], words[1:]
        if cmd in ("true", ":", "set", "sync", "chmod", "chown", "sleep", "umask", "export"):
            return 0, b"", b""
        if cmd in ("dirname", "basename") and len(args) == 1:
            fn = posixpath.dirname if cmd == "dirname" else posixpath.basename
            return 0, ((fn(args[0].rstrip("/")) or ("/" if cmd == "dirname" else "")) + "\n").encode(), b""
        if cmd == "grep":
            return self._grep(c, words, args, stdin)
        if cmd == "ps" and "ps" in c.extra:
            return 0, c.extra["ps"], b""
        if cmd == "dd":
            return self._dd(c, args, stdin)
        if cmd == "false":
            return 1, b"", b""
        if cmd in ("[", "test"):
            args = args[:-1] if cmd == "[" and args and args[-1] == "]" else args
            negate = bool(args) and args[0] == "!"
            args = args[1:] if negate else args
            if len(args) == 2 and args[0] in ("-f", "-e", "-d", "-s"):
                ok = self._exists(c, args[1], args[0])
                return (0 if ok != negate else 1), b"", b""
            if len(args) == 3 and args[1] in ("=", "==", "!="):
                ok = (args[0] == args[2]) == (args[1] != "!=")
                return (0 if ok != negate else 1), b"", b""
            if len(args) == 2 and args[0] in ("-n", "-z"):
                ok = bool(args[1]) == (args[0] == "-n")
                return (0 if ok != negate else 1), b"", b""
            return self._unmodelled(["test", *words])
        if cmd == "mkdir":
            return 0, b"", b""
        if cmd == "cat":
            files = [a for a in args if not a.startswith("-")]
            if not files:
                return 0, stdin, b""
            out = b""
            for f in files:
                data = self.read_file(c, f)
                if data is None:
                    return 1, out, f"cat: {f}: No such file or directory".encode()
                out += data
            return 0, out, b""
        if cmd == "printf":
            return 0, _printf(args).encode(), b""
        if cmd == "echo":
            newline = not (args and args[0] == "-n")
            args = args[1:] if args and args[0] == "-n" else args
            return 0, (" ".join(args) + ("\n" if newline else "")).encode(), b""
        if cmd in ("mv", "cp"):
            paths = [a for a in args if not a.startswith("-")]
            if len(paths) != 2:
                return self._unmodelled(words)
            data = self.read_file(c, paths[0])
            if data is None and c.extra.get("image_files") and self.resolve(c, paths[0])[0] == ("fs", c.id):
                data = f"<{c.image}:{paths[0]}>".encode()
            if data is None:
                return 1, b"", f"{cmd}: {paths[0]}: No such file or directory".encode()
            problem = self._write(c, paths[1], data, "rename" if cmd == "mv" else "copy")
            if problem:
                return 1, b"", problem.encode()
            if cmd == "mv":      # a rename: the destination is the source's inode, not a rewrite of its own
                src, dst = self.resolve(c, paths[0]), self.resolve(c, paths[1])
                inode = self.inodes.get((src[0], src[1]))
                self._remove(c, paths[0], False)
                if inode is not None:
                    self.inodes[(dst[0], dst[1])] = inode
                    self.writes[-1]["inode"] = inode
            return 0, b"", b""
        if cmd == "rm":
            recursive = any(a.startswith("-") and "r" in a.lower() for a in args)
            for p in [a for a in args if not a.startswith("-")]:
                self._remove(c, p, recursive)
            return 0, b"", b""
        if cmd == "tar":
            flags = " ".join(a for a in args if (a.startswith("-") and a != "-C") or a in ("x", "xf", "-xf"))
            if "c" in flags and "x" not in flags:
                return self._tar_create(c, args, words)
            if "x" not in flags or "-C" not in args:
                return self._unmodelled(words)
            dest = args[args.index("-C") + 1]
            try:
                with tarfile.open(fileobj=io.BytesIO(stdin)) as tar:
                    for member in tar.getmembers():
                        if member.isfile():
                            data = tar.extractfile(member).read()
                            problem = self._write(c, posixpath.join(dest, member.name), data)
                            if problem:
                                return 2, b"", problem.encode()
            except tarfile.TarError as exc:
                return 2, b"", f"tar: {exc}".encode()
            return 0, b"", b""
        return self._unmodelled(words)


_RANDOM_TOKEN = re.compile(r"\s*head -c [0-9]+ /dev/urandom\s*\|\s*base64(?: -w ?0)?(?:\s*\|\s*tr -d '[^']*')?\s*")
_GROUP_WORD = "\x05group"


def _groups(script: str):
    """`script` with each top-level `( body )` replaced by a word naming it (run by `_simple`), and the bodies;
    a whole script `{ body; } N>file` becomes `exec N>file; body` (the same shell, fd N open to its end).
    None for a `{ ... }` group anywhere else, or a group whose parentheses do not close."""
    head = re.fullmatch(r"\s*\{(?P<body>.*?);?\s*\}\s*(?P<redir>[0-9](?:>>|<>|>|<)\s*\S+)?\s*", script, re.S)
    if head and "{" not in head["body"] and "}" not in head["body"]:
        return (f"exec {head['redir']}; {head['body']}" if head["redir"] else head["body"]), {}
    out, groups, i, quote, at_start = [], {}, 0, "", True
    while i < len(script):
        ch = script[i]
        if quote:
            step = 2 if ch == "\\" and quote == '"' else 1
            quote = "" if ch == quote else quote
            out.append(script[i:i + step])
            i += step
            continue
        if ch in "'\"":
            quote, at_start = ch, False
        elif ch == "(" and at_start:
            depth, j, q = 1, i + 1, ""
            while j < len(script) and depth:
                cj = script[j]
                if q:
                    q = "" if cj == q else q
                elif cj in "'\"":
                    q = cj
                elif cj == "(":
                    depth += 1
                elif cj == ")":
                    depth -= 1
                j += 1
            if depth:
                return None
            key = f"g{len(groups)}"
            groups[key] = ("(", script[i + 1:j - 1])
            out.append(f" {_GROUP_WORD} {key} ")
            redir = re.match(r"\s*([0-9])(>>|<>|>|<)", script[j:])
            if redir:
                out.append(f"{redir[1]} {redir[2]}")
                j += redir.end()
            i, at_start = j, False
            continue
        elif ch in "{}" and at_start:
            return None
        if ch in ";\n&|":
            at_start = True
        elif not ch.isspace():
            at_start = script[max(0, i - 3):i + 1] in ("then", "else") or script[max(0, i - 1):i + 1] == "do"
        out.append(ch)
        i += 1
    return "".join(out), groups


_VARMARK = re.compile("\x01(\\w+)\x02")


def _premark(script: str, subs: dict) -> str:
    """`script` with each `$NAME`/`${NAME}` and `$(...)` outside single quotes replaced by a marker, so the
    value is put in after the words are split (and a single-quoted script, e.g. one handed to `sh -c` or
    `flock`, keeps its own `$1` for its own shell). `subs` receives each substitution's command."""
    out, i, sq, n = [], 0, False, len(script)
    while i < n:
        ch = script[i]
        if sq:
            out.append(ch)
            sq = ch != "'"
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(script[i:i + 2])
            i += 2
            continue
        if ch == "'" and not _in_double(out):
            sq = True
            out.append(ch)
            i += 1
            continue
        if ch == "$" and script[i + 1:i + 2] == "(":
            depth, j = 0, i + 1
            while j < n:
                depth += {"(": 1, ")": -1}.get(script[j], 0)
                if depth == 0:
                    break
                j += 1
            key = f"\x03{len(subs)}\x04"
            subs[key] = script[i + 2:j]
            out.append(key)
            i = j + 1
            continue
        m = re.match(r"\$(\w+)|\$\{(\w+)\}", script[i:])
        if m:
            out.append(f"\x01{m.group(1) or m.group(2)}\x02")
            i += m.end()
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _in_double(out: list) -> bool:
    text = "".join(out)
    count, k = 0, 0
    while k < len(text):          # unescaped double quotes outside single-quoted runs
        if text[k] == "\\":
            k += 2
            continue
        if text[k] == "'" and count % 2 == 0:
            end = text.find("'", k + 1)
            k = len(text) if end < 0 else end + 1
            continue
        if text[k] == '"':
            count += 1
        k += 1
    return count % 2 == 1


class _Exit(Exception):
    def __init__(self, rc: int) -> None:
        super().__init__(rc)
        self.rc = rc


class _Syntax(Exception):
    pass


def _printf(args: list[str]) -> str:
    if not args:
        return ""
    fmt, values = args[0], list(args[1:])

    def unescape(s: str) -> str:
        return s.replace("\\n", "\n").replace("\\t", "\t").replace("\\\\", "\\")

    out, i = [], 0
    pieces = re.split(r"(%[-0-9]*[sd]|%%)", fmt)
    for piece in pieces:
        if piece == "%%":
            out.append("%")
        elif re.fullmatch(r"%[-0-9]*[sd]", piece):
            value = values[i] if i < len(values) else ""
            i += 1
            if piece.endswith("d"):
                value = str(int(value or 0))
            spec = piece[1:-1]
            out.append(f"{value:{'<' if spec.startswith('-') else '>'}{spec.lstrip('-')}}" if spec else value)
        else:
            out.append(unescape(piece))
    return "".join(out)
