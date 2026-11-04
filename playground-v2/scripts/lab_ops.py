#!/usr/bin/env python3
"""The real lab operations behind frozen cases (#1347): capture's snapshot steps, the frozen
engine the launcher serves a run from, and the Elasticsearch clock and fingerprint both use.

`capture_case.py` and `launch_frozen.py` drive these through one `LabOps` object; their tests
replace it with fakes, so only `es_now` and `fingerprint` are exercised hermetically (through
the `run=` seam). Everything that moves images, volumes and containers is checked by the
operator on the lab.

Every call reaches the live stack with `docker --context soc-playground ...`, as the runner and
the chaos control do. Elasticsearch is reached by curl inside its own container; the password is
expanded there into curl's config on a file descriptor, never onto a command line, and request
bodies ride on stdin.

The frozen engine (D2) is a Docker-in-Docker container on the lab server. It holds inert copies
of the role hosts (committed images and copied volumes, no agent, no baseline, no shipping), the
five stubs loaded from their dumps with their clocks pinned at `as_of`, and stand-ins named like
the Elasticsearch and Kibana containers that forward to the live cluster. The launcher points a
copy of the operator's Docker config at it under the playground's own context name.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

import yaml

HERE = Path(__file__).resolve().parent
PLAYGROUND = HERE.parent
REPO = PLAYGROUND.parent

DOCKER_CONTEXT = "soc-playground"
ES_CONTAINER = "elasticsearch"
EVENTS_PATTERN = "logs-*"
ALERTS_PATTERN = ".internal.alerts-security.alerts-default-*"

# ES|QL answers at most 10000 rows a request; a page that comes back full may have been cut.
PAGE_LIMIT = 10000
PAGE = timedelta(days=1)

# The verb's fixed argv (host_state_adapter proc_tree); the shim answers exactly this.
PS_ARGV = ["ps", "-eo", "pid,ppid,user,stat,etime,cmd", "--forest"]
SHIM_IN_IMAGE = "/opt/soc-playground/ps-shim"
TREE_IN_REPLICA = "/opt/soc-playground/ps-tree"
# Role-host volumes the frozen copy restores (O4); mounted certs and tokens are not copied.
HOST_VOLUMES = ("/var/log", "/var/lib/elastic-agent")
STUBS = ("cmdb", "identity", "threat-intel", "change-mgmt", "ticket-server")

ENGINE_CONTAINER = "lab-engine"
ENGINE_IMAGE = "docker:27-dind"
# The engine's daemon listens only on this socket, in a lab-server directory bind-mounted into
# the engine; nothing listens on a network, so no container on Elasticsearch's network (a role
# host, a compromised one included) can reach it. The launcher reaches it over ssh.
ENGINE_SOCKET_DIR = "/run/soc-lab-engine"
ENGINE_SOCKET = f"{ENGINE_SOCKET_DIR}/docker.sock"
ENGINE_NETWORK = "lab"
# The Elasticsearch and Kibana stand-ins' image: built and saved by capture as a freeze part, so
# loading a frozen copy installs nothing and needs no outbound network.
STAND_IN_IMAGE = "local/lab-stand-in:latest"
STAND_IN_DOCKERFILE = HERE / "stand-in.Dockerfile"
# How long a loaded frozen copy has to answer before the launch is refused.
READY_TIMEOUT_S = 120.0


class LabOpsError(RuntimeError):
    """A lab command failed, or Elasticsearch answered with an error."""


def utc(value: Any) -> datetime:
    """`value` (a datetime, or ISO-8601 text) as aware UTC; naive is read as UTC. The one reader
    of freeze and fingerprint moments, shared by capture and the launcher."""
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def stamp(dt: datetime) -> str:
    """`dt` as `YYYY-MM-DDTHH:MM:SS.mmmZ`: the one spelling of every freeze and fingerprint
    moment, so the freeze and the post-run check can never disagree on one."""
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _cut_clause(as_of: datetime, arrived_by: Optional[datetime]) -> dict:
    """The product's one cut builder (P5/D12): what a frozen run reads is what is fingerprinted.
    Lab code imports product code, never the reverse (#1215)."""
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from defender.integrations.elastic_adapter import cut_clause

    return cut_clause(as_of, arrived_by)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class LabOps:
    """`run=` replaces subprocess.run; `popen=` replaces subprocess.Popen (the engine tunnel)."""

    def __init__(self, run: Any = subprocess.run, *, context: str = DOCKER_CONTEXT,
                 es_container: str = ES_CONTAINER, events_pattern: str = EVENTS_PATTERN,
                 alerts_pattern: str = ALERTS_PATTERN, popen: Any = subprocess.Popen,
                 alert_timeout_s: float = 1800.0, poll_s: float = 30.0,
                 ready_timeout_s: float = READY_TIMEOUT_S) -> None:
        self._run, self._popen = run, popen
        self.context, self.es_container = context, es_container
        self.events_pattern, self.alerts_pattern = events_pattern, alerts_pattern
        self.alert_timeout_s, self.poll_s = alert_timeout_s, poll_s
        self.ready_timeout_s = ready_timeout_s
        self._tunnel: Any = None
        self._tunnel_dir: Optional[Path] = None
        self._engine_host: Optional[str] = None

    # -- transport ---------------------------------------------------------------------------

    def _docker(self, *args: str, host: Optional[str] = None, check: bool = True,
                **kw: Any) -> Any:
        target = ["-H", host] if host else ["--context", self.context]
        kw.setdefault("capture_output", True)
        proc = self._run(["docker", *target, *args], **kw)
        if check and proc.returncode != 0:
            err = proc.stderr.decode(errors="replace") if isinstance(proc.stderr, bytes) else proc.stderr
            raise LabOpsError(f"docker {' '.join(args[:3])}: rc={proc.returncode} {(err or '').strip()}")
        return proc

    def _es(self, method: str, path: str, body: Any = None) -> Any:
        script = ('curl -s -k -K <(printf \'user = "elastic:%s"\\n\' "$ELASTIC_PASSWORD") '
                  '-w "\\n%{http_code}" "$@"')
        # `-i` attaches stdin, which carries the body.
        argv = ["docker", "--context", self.context, "exec", *(["-i"] if body is not None else []),
                self.es_container, "bash", "-c", script, "curl", "-X", method]
        kw: dict[str, Any] = {"capture_output": True, "text": True}
        if body is not None:
            argv += ["-H", "Content-Type: application/json", "--data-binary", "@-"]
            kw["input"] = json.dumps(body)
        argv.append(f"https://localhost:9200{path}")
        proc = self._run(argv, **kw)
        if proc.returncode != 0:
            raise LabOpsError(f"elasticsearch {method} {path}: rc={proc.returncode} "
                              f"{(proc.stderr or '').strip()}")
        text, _, status = proc.stdout.rstrip().rpartition("\n")
        try:
            code = int(status.strip())
        except ValueError:
            raise LabOpsError(f"elasticsearch {method} {path}: no HTTP status in "
                              f"{proc.stdout[-200:]!r}") from None
        payload = json.loads(text) if text.strip() else {}
        if not 200 <= code < 300:
            raise LabOpsError(f"elasticsearch {method} {path}: HTTP {code}: {str(payload)[:500]}")
        return payload

    def _esql(self, query: str, flt: Optional[dict] = None) -> list[list[Any]]:
        body: dict[str, Any] = {"query": query}
        if flt is not None:
            body["filter"] = flt
        return self._es("POST", "/_query", body).get("values") or []

    # -- Elasticsearch: clock, refresh, fingerprint ------------------------------------------

    def es_now(self) -> str:
        """Elasticsearch's own clock, never the local one (captured_at is the arrival cut)."""
        rows = self._esql("ROW t = NOW()")
        if not rows or not rows[0]:
            raise LabOpsError("elasticsearch answered no clock reading")
        return str(rows[0][0])

    def refresh(self) -> None:
        self._es("POST", f"/{self.events_pattern},{self.alerts_pattern}/_refresh"
                 "?expand_wildcards=open,hidden&ignore_unavailable=true")

    def fingerprint(self, window: Any, as_of: Any, arrived_by: Any) -> dict[str, list[int]]:
        """Per backing index x hour inside `[window[0], as_of]`: COUNT(*) and SUM(_version), with
        the read path's cut clause as the request filter. Paged by day so no page nears the row
        cap; a full page is refused rather than trusted (r6.1)."""
        lower, upper = utc(window[0]), utc(as_of)
        flt = _cut_clause(upper, utc(arrived_by) if arrived_by is not None else None)
        out: dict[str, list[int]] = {}
        # Page boundaries after the first sit on whole hours, so each hour bucket belongs to
        # exactly one page: [floor_hour(start), end), the last page closed at as_of.
        first_hour = lower.replace(minute=0, second=0, microsecond=0)
        for pattern in (self.events_pattern, self.alerts_pattern):
            start, page = lower, 1
            while start < upper:
                end = min(first_hour + PAGE * page, upper)
                last = end == upper
                query = (
                    f"FROM {pattern} METADATA _index, _version\n"
                    f'| WHERE @timestamp >= TO_DATETIME("{stamp(start)}") '
                    f'AND @timestamp {"<=" if last else "<"} TO_DATETIME("{stamp(end)}")\n'
                    "| EVAL hour = DATE_TRUNC(1 hour, @timestamp)\n"
                    "| STATS docs = COUNT(*), versions = SUM(_version) BY _index, hour\n"
                    f"| LIMIT {PAGE_LIMIT}"
                )
                rows = self._esql(query, flt)
                if len(rows) >= PAGE_LIMIT:
                    raise LabOpsError(f"fingerprint page {stamp(start)}..{stamp(end)} of "
                                      f"{pattern} came back with {len(rows)} rows (the cap): "
                                      "it may be truncated; refusing")
                owned_from = start.replace(minute=0, second=0, microsecond=0)
                for count, versions, index, hour in rows:
                    bucket = utc(hour)
                    # A bucket outside the page that owns it is not this page's to count.
                    if not (owned_from <= bucket and (bucket <= end if last else bucket < end)):
                        continue
                    out[f"{index}|{str(hour)[:13]}"] = [int(count), int(versions or 0)]
                start, page = end, page + 1
        return out

    # -- capture: fire, alert, snapshot, revert ----------------------------------------------

    def activate(self, chaos: str, seed: int, lock_token: str) -> str:
        """Activate the chaos profile under the capture's token and return its ledger ref. The
        fault stays live until capture reverts it: capture is its only reverter (r6.2)."""
        from chaos import lock

        store = lock.DockerLockStore(context=self.context)
        record = _chaos_ctl().activate(chaos, seed=seed, lock_store=store, lock_token=lock_token)
        return record["ledger_ref"]

    def fire(self, scenario: str, seed: int, lock_token: str) -> dict:
        """Fire the scenario under the capture's token. Never touches a fault: one that fails
        raises with whatever capture activated still live, for capture to revert."""
        runner = _load_runner()
        from chaos import lock

        store = lock.DockerLockStore(context=self.context)
        catalog = runner.load_catalog()
        started = datetime.now(timezone.utc)
        run_id, _, _ = runner.run_scenario(
            catalog[scenario], seed, {}, False, lock_store=store, lock_token=lock_token)
        return {"run_id": run_id, "started_at": stamp(started),
                "target_host": catalog[scenario]["target_host"]}

    def wait_alert(self, fired: dict) -> dict:
        """The first alert of the case's rule (`fired["rule_id"]`) at or after the scenario fired,
        on its target host; polled, since rules run every 5 minutes (C8). Another rule's alert on
        the same host (baseline, a neighbour rule) is never taken for the case's."""
        query = {"size": 1, "sort": [{"@timestamp": "asc"}], "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": fired["started_at"]}}},
            {"term": {"host.name": fired["target_host"]}},
            {"term": {"kibana.alert.rule.rule_id": fired["rule_id"]}}]}}}
        deadline = time.monotonic() + self.alert_timeout_s
        while True:
            hits = self._es("POST", f"/{self.alerts_pattern}/_search", query)["hits"]["hits"]
            if hits:
                return hits[0]["_source"]
            if time.monotonic() > deadline:
                raise LabOpsError(f"no {fired['rule_id']} alert on {fired['target_host']} since "
                                  f"{fired['started_at']}")
            time.sleep(self.poll_s)

    def hosts(self) -> list[str]:
        inventory = yaml.safe_load((PLAYGROUND / "hosts" / "inventory.yaml").read_text())
        return [h["name"] for h in inventory["hosts"]]

    def proc_tree(self, dest: Path) -> list[str]:
        """Each role host's process tree as the proc-tree verb would read it (D6)."""
        dest.mkdir(parents=True, exist_ok=True)
        names = []
        for host in self.hosts():
            proc = self._docker("exec", host, *PS_ARGV)
            name = f"proc-tree-{host}.txt"
            (dest / name).write_bytes(proc.stdout)
            names.append(name)
        return names

    def stub_dumps(self, dest: Path) -> list[str]:
        """Each stub's state in the shape its own seed loader reads, plus the stub images and
        the stand-ins' image: everything the frozen engine runs besides the hosts."""
        dest.mkdir(parents=True, exist_ok=True)
        names = []
        changes = self._stub_get("change-mgmt", "/changes")["changes"]
        names.append(_write(dest / "stub-change-mgmt.yaml", yaml.safe_dump(changes, sort_keys=False)))
        tickets = self._stub_get("ticket-server", "/tickets")["tickets"]
        names.append(_write(dest / "stub-ticket-server.json", json.dumps(tickets, indent=1)))
        indicators = self._stub_get("threat-intel", "/indicators")["indicators"]
        names.append(_write(dest / "stub-threat-intel.json", json.dumps(indicators, indent=1)))
        listed = [h["name"] for h in self._stub_get("cmdb", "/hosts")["hosts"]]
        overlays = {}
        for name in sorted(set(listed) | set(self.hosts())):
            overlay = self._stub_get("cmdb", f"/admin/overlay/{name}").get("overlay")
            if overlay is not None:
                overlays[name] = overlay
        names.append(_write(dest / "stub-cmdb-overlays.json", json.dumps(overlays, indent=1)))
        for stub in STUBS:
            names.append(self._save_image(self._image_of(stub), dest / f"image-{stub}.tar"))
        with open(STAND_IN_DOCKERFILE, "rb") as fh:
            self._docker("build", "-t", STAND_IN_IMAGE, "-", stdin=fh)
        names.append(self._save_image(STAND_IN_IMAGE, dest / "image-stand-in.tar"))
        return names

    def commit_hosts(self, dest: Path, as_of: Any = None) -> list[str]:
        """Commit each role host (the commit pauses it) and save the image."""
        dest.mkdir(parents=True, exist_ok=True)
        names = []
        for host in self.hosts():
            tag = f"local/{host}:latest"
            self._docker("commit", "--pause=true", host, tag)
            try:
                names.append(self._save_image(tag, dest / f"image-{host}.tar"))
            finally:
                self._docker("image", "rm", tag, check=False)
        return names

    def copy_volumes(self, dest: Path) -> list[str]:
        """/var/log and /var/lib/elastic-agent of each role host, read through a throwaway
        container that mounts the host's volumes read-only."""
        dest.mkdir(parents=True, exist_ok=True)
        names = []
        for host in self.hosts():
            image = self._image_of(host)
            for mount in HOST_VOLUMES:
                name = f"volume-{host}{mount.replace('/', '-')}.tar"
                with open(dest / name, "wb") as fh:
                    self._docker("run", "--rm", "--volumes-from", f"{host}:ro", "--entrypoint",
                                 "tar", "--network", "none", image, "-C", mount, "-cf", "-", ".",
                                 capture_output=False, stdout=fh, stderr=subprocess.PIPE)
                names.append(name)
        return names

    def revert(self, ledger_ref: str) -> None:
        _chaos_ctl().revert(ledger_ref)

    def _stub_get(self, stub: str, path: str) -> Any:
        script = ("import sys, urllib.request\n"
                  f"sys.stdout.write(urllib.request.urlopen('http://127.0.0.1:8080{path}', "
                  "timeout=10).read().decode())\n")
        proc = self._docker("exec", stub, "python3", "-c", script, text=True)
        return json.loads(proc.stdout)

    def _image_of(self, container: str) -> str:
        return self._docker("inspect", "--format", "{{.Config.Image}}", container,
                            text=True).stdout.strip()

    def _save_image(self, image: str, path: Path) -> str:
        with open(path, "wb") as fh:
            self._docker("save", image, capture_output=False, stdout=fh, stderr=subprocess.PIPE)
        return path.name

    # -- the frozen engine --------------------------------------------------------------------

    def load_frozen(self, parts_dir: Path, as_of: Any) -> dict:
        """A fresh frozen copy from the parts in `parts_dir`, pinned at `as_of`."""
        as_of_text = stamp(utc(as_of))
        self._start_engine()
        host = self._engine_host
        assert host is not None
        self._docker("network", "create", ENGINE_NETWORK, host=host)
        for image_part in sorted(parts_dir.glob("image-*.tar")):
            with open(image_part, "rb") as fh:
                self._docker("load", host=host, stdin=fh)
        self._load_hosts(parts_dir, host)
        self._load_stubs(parts_dir, host, as_of_text)
        self._start_stand_ins(parts_dir, host)
        self._wait_ready(host)
        return {"docker_host": host}

    def teardown(self) -> None:
        try:
            self._docker("rm", "-f", "-v", ENGINE_CONTAINER, check=False)
        finally:
            if self._tunnel is not None:
                self._tunnel.terminate()
                self._tunnel = None
            if self._tunnel_dir is not None:
                shutil.rmtree(self._tunnel_dir, ignore_errors=True)
                self._tunnel_dir = None
            self._engine_host = None

    def _start_engine(self) -> None:
        # The engine's image, command and labels match nothing the SOAR reaper stops
        # (CLAUDE.md: no `python app.py`, no `shuffle` label value).
        self._docker("rm", "-f", "-v", ENGINE_CONTAINER, check=False)
        # On Elasticsearch's own network, so the stand-ins inside can forward to it by address
        # (Docker isolates one bridge from another).
        network = self._docker("inspect", "--format",
                               "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}",
                               self.es_container, text=True).stdout.split()[0]
        # `dockerd` named as the command: the image's entrypoint adds a `tcp://0.0.0.0:2375`
        # listener whenever the command starts with a flag, and leaves an explicit one alone.
        self._docker("run", "-d", "--privileged", "--name", ENGINE_CONTAINER, "--network", network,
                     "-v", f"{ENGINE_SOCKET_DIR}:{ENGINE_SOCKET_DIR}",
                     ENGINE_IMAGE, "dockerd", f"--host=unix://{ENGINE_SOCKET}")
        endpoint = self._docker("context", "inspect", self.context, "--format",
                                "{{.Endpoints.docker.Host}}", text=True).stdout.strip()
        if endpoint.startswith("ssh://"):
            # ssh forwards a local socket to the engine's socket on the lab server.
            url = urlsplit(endpoint)
            # Under /tmp whatever TMPDIR says: a unix socket path is capped near 108 bytes.
            self._tunnel_dir = Path(tempfile.mkdtemp(dir="/tmp"))
            local = self._tunnel_dir / "docker.sock"
            target = f"{url.username}@{url.hostname}" if url.username else str(url.hostname)
            self._tunnel = self._popen(
                ["ssh", "-N", "-o", "ExitOnForwardFailure=yes",
                 *(["-p", str(url.port)] if url.port else []),
                 "-L", f"{local}:{ENGINE_SOCKET}", target])
            self._engine_host = f"unix://{local}"
        elif endpoint.startswith("unix://"):
            # On the lab server itself.
            self._engine_host = f"unix://{ENGINE_SOCKET}"
        else:
            raise LabOpsError(f"the frozen engine is reached over an ssh context or on the lab "
                              f"server itself; context {self.context!r} is {endpoint!r}")
        deadline = time.monotonic() + 120
        while self._docker("version", host=self._engine_host, check=False).returncode != 0:
            if time.monotonic() > deadline:
                raise LabOpsError("the frozen engine did not come up")
            time.sleep(2)

    def _load_hosts(self, parts_dir: Path, host: str) -> None:
        for name in self.hosts():
            image = f"local/{name}:latest"
            mounts = []
            for mount in HOST_VOLUMES:
                volume = f"{name}{mount.replace('/', '_')}"
                self._docker("volume", "create", volume, host=host)
                with open(parts_dir / f"volume-{name}{mount.replace('/', '-')}.tar", "rb") as fh:
                    self._docker("run", "--rm", "-i", "--network", "none", "-v", f"{volume}:/v",
                                 "--entrypoint", "tar", image, "-C", "/v", "-xf", "-",
                                 host=host, stdin=fh)
                mounts += ["-v", f"{volume}:{mount}"]
            # Inert (D2 i): the image's entrypoint (agent enrolment, baseline, shipping) never
            # runs; the container only holds the filesystem for the host-state verbs.
            self._docker("create", "--name", name, "--hostname", name, "--network", ENGINE_NETWORK,
                         *mounts, "-e", f"V2_PS_SHIM_TREE={TREE_IN_REPLICA}",
                         "--entrypoint", "/usr/bin/tini", image, "--", "sleep", "infinity",
                         host=host)
            self._docker("cp", str(parts_dir / f"proc-tree-{name}.txt"),
                         f"{name}:{TREE_IN_REPLICA}", host=host)
            self._docker("start", name, host=host)
            # The baked shim answers the proc-tree verb's argv from the captured tree (D6).
            self._docker("exec", name, "ln", "-sf", SHIM_IN_IMAGE, "/usr/local/bin/ps", host=host)

    def _load_stubs(self, parts_dir: Path, host: str, as_of: str) -> None:
        seeds = {"change-mgmt": ("stub-change-mgmt.yaml", "CHANGE_SEED_PATH"),
                 "ticket-server": ("stub-ticket-server.json", "TICKET_SEED_PATH"),
                 "threat-intel": ("stub-threat-intel.json", "TI_SEED_PATH")}
        for stub in STUBS:
            image = _image_in_tar(parts_dir / f"image-{stub}.tar")
            env = ["-e", f"V2_STUB_AS_OF={as_of}", "-e", "STANDING_REFRESH_SECONDS=0",
                   # Standing CRs were materialized into the dump; none is derived again.
                   "-e", "CHANGE_STANDING_PATH=/nonexistent"]
            seed = seeds.get(stub)
            if seed:
                env += ["-e", f"{seed[1]}=/srv/seed/{seed[0]}"]
            self._docker("create", "--name", stub, "--network", ENGINE_NETWORK, *env, image,
                         host=host)
            if seed:
                # `docker cp` creates a missing destination only for a directory source.
                with tempfile.TemporaryDirectory() as staged:
                    shutil.copy(parts_dir / seed[0], Path(staged) / seed[0])
                    self._docker("cp", staged, f"{stub}:/srv/seed", host=host)
            self._docker("start", stub, host=host)
        overlays = json.loads((parts_dir / "stub-cmdb-overlays.json").read_text())
        script = ("import json, sys, time, urllib.request\n"
                  "for name, body in json.load(sys.stdin).items():\n"
                  "    for _ in range(60):\n"
                  "        try:\n"
                  "            req = urllib.request.Request('http://127.0.0.1:8080/admin/overlay/' + name,\n"
                  "                data=json.dumps(body).encode(), method='PUT',\n"
                  "                headers={'Content-Type': 'application/json'})\n"
                  "            urllib.request.urlopen(req, timeout=5).read(); break\n"
                  "        except OSError:\n"
                  "            time.sleep(1)\n"
                  "    else:\n"
                  "        sys.exit('cmdb overlay ' + name + ' not loaded')\n")
        self._docker("exec", "-i", "cmdb", "python3", "-c", script, host=host,
                     input=json.dumps(overlays), text=True)

    def _start_stand_ins(self, parts_dir: Path, host: str) -> None:
        """Containers named like Elasticsearch and Kibana that carry sh, curl and the live
        password, and forward their localhost port to the live service by address (D2 ii). Their
        image is the one capture saved (`stub_dumps`), so nothing is installed here."""
        image = _image_in_tar(parts_dir / "image-stand-in.tar")
        password = self._docker("exec", self.es_container, "printenv", "ELASTIC_PASSWORD",
                                text=True).stdout.strip()
        for name, port in ((self.es_container, 9200), ("kibana", 5601)):
            address = self._docker(
                "inspect", "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name,
                text=True).stdout.split()[0]
            with tempfile.NamedTemporaryFile("w", suffix=".env") as env_file:
                env_file.write(f"ELASTIC_PASSWORD={password}\n")
                env_file.flush()
                self._docker(
                    "run", "-d", "--name", name, "--network", ENGINE_NETWORK,
                    "--env-file", env_file.name, image,
                    "socat", f"TCP-LISTEN:{port},fork,reuseaddr,bind=127.0.0.1",
                    f"TCP:{address}:{port}",
                    host=host)

    def _wait_ready(self, host: str) -> None:
        """Return once the frozen copy answers as a run will ask it: the Elasticsearch stand-in
        reaches the live cluster with the password, the Kibana stand-in reaches Kibana, and every
        stub serves. A copy that never does refuses the launch, so no run starts with a system
        down."""
        es = ('curl -s -k -o /dev/null -w "%{http_code}" '
              '-K <(printf \'user = "elastic:%s"\\n\' "$ELASTIC_PASSWORD") https://localhost:9200')
        kibana = 'curl -s -o /dev/null -w "%{http_code}" http://localhost:5601/api/status'
        health = ("import urllib.request\n"
                  "urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=5).read()\n")
        waiting = {self.es_container: (["bash", "-c", es], lambda out: out == "200"),
                   "kibana": (["bash", "-c", kibana], lambda out: out not in ("", "000"))}
        waiting.update({stub: (["python3", "-c", health], lambda out: True) for stub in STUBS})
        deadline = time.monotonic() + self.ready_timeout_s
        while True:
            for name, (argv, answered) in list(waiting.items()):
                proc = self._docker("exec", name, *argv, host=host, check=False, text=True)
                if proc.returncode == 0 and answered((proc.stdout or "").strip()):
                    del waiting[name]
            if not waiting:
                return
            if time.monotonic() > deadline:
                raise LabOpsError("the frozen copy did not answer: " + ", ".join(sorted(waiting)))
            time.sleep(2)


def _write(path: Path, text: str) -> str:
    path.write_text(text)
    return path.name


def _image_in_tar(path: Path) -> str:
    """The first tag a `docker save` archive carries."""
    with tarfile.open(path) as tar:
        member = tar.extractfile("manifest.json")
        assert member is not None
        return json.load(member)[0]["RepoTags"][0]


def _load_runner() -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location("attack_runner", PLAYGROUND / "attacks" / "runner.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _chaos_ctl() -> Any:
    if str(PLAYGROUND) not in sys.path:
        sys.path.insert(0, str(PLAYGROUND))
    from chaos import ctl

    return ctl
