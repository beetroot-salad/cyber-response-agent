#!/usr/bin/env python3
"""The real lab operations behind frozen cases (#1347 r6.4): what capture takes at T, what
make-a-case lists, and what the launcher drives to serve a run from a frozen copy.

`capture_case.py`, `make_case.py` and `launch_frozen.py` drive these through one `LabOps`; their
tests drive this class too, faking only docker (`run=`) and the clusters behind it. What needs the
real lab (images, the shim under TLS, restore timings) is checked by the operator (runbook,
deferred verification).

Topology. The *frozen engine* is a Docker-in-Docker container (`lab-engine`) on the lab server,
reached with `docker --context <context> exec lab-engine docker ...`; its daemon listens on a unix
socket only. Inside it (network `lab`): the frozen Elasticsearch (`elasticsearch`, the live image,
the live node's certificate mounted from the lab's certs volume, `LD_PRELOAD` of the D15 wall-clock
shim reading its offset from a file on the engine's state volume), the five stubs loaded from the freeze's dump and pinned at T, and the
frontend: the lab's edge program (`edge/edge.py`, the same one live runs, key check off: the engine
is reached only through the operator's SSH forward), publishing every port of `lab-surface.json`
on the engine's loopback and admitting only the declared surface, so a frozen run cannot read the
case's chaos overlay through `GET /admin/overlay`. The *frozen proxy* is a second container on the
deployment network (next to the live credential proxy), the product's proxy program unmodified,
with its own audit file and a resolver (`--add-host`) mapping the tenant's declared host names to
the ssh-forwarded endpoint of that frontend.

Host state (#1391 r6 O9): `serve_hosts` builds one inert replica per host the freeze committed
(`image-<host>.tar`), named as the host, with no network, an idle entrypoint and no healthcheck;
its `/var/log` and `/var/lib/elastic-agent` copies and its captured process tree mounted
read-only, and today's `ps` shim (`hosts/base/ps-shim`) mounted as `ps` on its PATH, so the
process list is the tree captured at T. The lab's endpoint-query service then answers host-state
for those hosts, with nothing inspectable (`container-inspect` is #1347's named gap). Images and
extracted parts are cached in the engine by the part's sha256 (a part loaded or extracted only
once, an interrupted extract never a cache hit); `purge_host_cache` removes a freeze's.

Every restore goes into a fresh node (D25): the node container and its data volume
(`frozen-es-data`) are discarded and a new node starts empty; the copy-state marker lives on the
engine's state volume, so it outlives the wipe. The node's clock offset (D15 revised) is a fixed
24-byte record (a signed decimal number of seconds, space-padded, newline-ended) in
`CLOCK_FILE`: created before the node starts and only ever rewritten in place at byte 0, never
truncated or replaced, because the shim maps that file once and reads it on every clock call.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

HERE = Path(__file__).resolve().parent
PLAYGROUND = HERE.parent
REPO = PLAYGROUND.parent
for _path in (HERE, REPO):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import frozen_copy  # noqa: E402

DOCKER_CONTEXT = "soc-playground"
ES_CONTAINER = "elasticsearch"
RULES_PART = "detection-rules.tar"
STUBS_PART = "stubs.tar"
#: The lab's public surface, one table (#1391 r6 L3): ports, the services behind them, the
#: process-list argv. The edge, the endpoint-query service and the firewall agree with it.
SURFACE = json.loads((PLAYGROUND / "lab-surface.json").read_text())
_SYSTEMS = SURFACE["systems"]
STUBS = {spec["service"]: int(spec["port"]) for name, spec in _SYSTEMS.items()
         if name not in ("host-state", "elastic")}
HOST_STATE_SERVICE = _SYSTEMS["host-state"]["service"]
HOST_STATE_PORT = int(_SYSTEMS["host-state"]["port"])
ES_PORT = int(_SYSTEMS["elastic"]["port"])
# What `content_digest` reads of each stub: its whole store, through a read the stub already serves.
STUB_STATE = {"cmdb": "/hosts", "threat-intel": "/indicators", "change-mgmt": "/changes",
              "ticket-server": "/tickets", "identity": "/users"}
FRONTEND_PORTS = (*STUBS.values(), HOST_STATE_PORT, ES_PORT)
FRONTEND_BASE = 10000    # the engine publishes frontend port p on the lab server's loopback at BASE+p
HOST_VOLUMES = ("/var/log", "/var/lib/elastic-agent")   # certs and tokens are never copied
PS_ARGV = list(SURFACE["ps_argv"])
WATCHER = "alert-ticket-watcher"

ENGINE = "lab-engine"
ENGINE_IMAGE = "docker:27-dind"
ENGINE_NETWORK = "lab"
STATE_DIR = "/lab/state"                  # inside the engine, on a volume that outlives it
MARKER_FILE = f"{STATE_DIR}/copy-state.json"
CLOCK_DIR = f"{STATE_DIR}/clock"          # the node's clock offset, shared with the node read-only
CLOCK_FILE = f"{CLOCK_DIR}/offset"
NODE_CLOCK_DIR = "/lab/clock"             # where the node sees CLOCK_DIR
OFFSET_RECORD = 24                        # bytes: the shim maps exactly this record
ES_DATA_VOLUME = "frozen-es-data"
ES_ENV_FILE = f"{STATE_DIR}/es.env"       # the frozen cluster's own elastic password, never a freeze part
SHIM_DIR, SHIM_FILE = "/lab/shim", "clockshim.so"
CERTS_DIR, REPO_DIR = "/lab/certs", "/lab/repo"
SEED_DIR = "/lab/seed"
SHIM_IMAGE = "local/clockshim:latest"
SHIM_CONTEXT = PLAYGROUND / "clockshim"
DEFAULT_ES_IMAGE = "docker.elastic.co/elasticsearch/elasticsearch:9.3.3"
FROZEN_PROXY = "frozen-credential-proxy"
FRONTEND = "frontend"                     # the engine's one edge container, every port of SURFACE
EDGE_IMAGE = "soc-playground/edge:local"
QUERY_IMAGE = "soc-playground/endpoint-query:local"
PS_SHIM = PLAYGROUND / "hosts" / "base" / "ps-shim"
HOST_SHIM_DIR = "/lab/hostshim"           # in the engine's own filesystem: today's shim, bound into replicas
QUERY_DIR = "/lab/endpoint-query"         # in the engine: the service's host lists
HOST_PARTS_DIR = f"{STATE_DIR}/host-parts"   # `<key>.done`: a part's extract finished
REPLICA_TREE_DIR = "/lab/tree"            # in a replica: its captured process tree
READONLY_PASSWORD_ENV = "V2_DEFENDER_READONLY_PASSWORD"
PROXY_PORT = 8411
RO_ROLE = "frozen_readonly"


class LabOpsError(RuntimeError):
    """A lab command failed, or Elasticsearch answered with an error."""


class NotConfigured(LabOpsError):
    """A setting the operation needs is unset (a runs directory, a parts directory, a tenant
    directory): a refusal, never an empty answer."""


def _text(value: Any) -> str:
    return value.decode(errors="replace") if isinstance(value, bytes) else (value or "")


def cmdb_patch(mutation: dict) -> dict:
    """The shallow-merge body the CMDB stub's `POST /admin/overlay/<host>` takes for a mutation
    (the same patch `chaos/ctl.py` pushes live)."""
    if mutation["kind"] == "field-flip":
        return {mutation["field"]: mutation["new_value"]}
    return dict(mutation["new_value"])


class FrozenEs:
    """The chaos seam's `es_request` for the FROZEN cluster: curl inside its container, the
    credential expanded from the container's own environment into curl's config on a descriptor,
    never onto a command line. Never goes through the frozen proxy."""

    SCRIPT = ('curl -s -k -K <(printf \'user = "elastic:%s"\\n\' "$ELASTIC_PASSWORD") '
              '-w "\\n%{http_code}" "$@"')

    def __init__(self, ops: LabOps) -> None:
        self._ops = ops

    def es_request(self, method: str, path: str, body: Any = None) -> Any:
        args = ["-X", method.upper()]
        kw: dict[str, Any] = {}
        if body is not None:
            args += ["-H", "Content-Type: application/json", "--data-binary", "@-"]
            kw["input"] = json.dumps(body)
        proc = self._ops._inner("exec", *(["-i"] if body is not None else []), ES_CONTAINER,
                                "bash", "-c", self.SCRIPT, "curl", *args,
                                f"https://localhost:{ES_PORT}{path}", text=True, check=False, **kw)
        text, _, status = _text(proc.stdout).rstrip().rpartition("\n")
        try:
            code = int(status.strip())
        except ValueError:
            # No status line at all: docker could not run curl (the node is stopped or missing).
            raise LabOpsError(f"frozen elasticsearch {method} {path}: rc={proc.returncode} "
                              f"{_text(proc.stderr).strip()[:300]} {_text(proc.stdout)[-200:]!r}") from None
        if code in (0, 502, 503, 504):   # 0 (`000`): curl could not connect (exit 7), the node is booting
            raise frozen_copy.NodeNotReady(f"frozen elasticsearch {method} {path}: HTTP {code} "
                                           f"(curl exit {proc.returncode})")
        if proc.returncode != 0:
            raise LabOpsError(f"frozen elasticsearch {method} {path}: curl exit {proc.returncode} "
                              f"{_text(proc.stderr).strip()[:300]}")
        payload = json.loads(text) if text.strip() else {}
        if not 200 <= code < 300:
            raise LabOpsError(f"frozen elasticsearch {method} {path}: HTTP {code}: {str(payload)[:500]}")
        return payload


class LabOps:
    """`run=` replaces `subprocess.run`. Every command is `docker --context <context> ...`
    (the frozen proxy alone goes to the engine the deployment runs on: `proxy_context`)."""

    def __init__(self, run: Any = subprocess.run, *, context: str = DOCKER_CONTEXT,
                 tenant_dir: Any = None, tenant_hosts: Any = (), frozen_endpoint: str | None = None,
                 es: Any = None,
                 audit_path: str | None = None, live_audit_path: str | None = None,
                 proxy_context: str | None = None,
                 proxy_image: str = "cyber-response-agent_devcontainer-credential-proxy",
                 live_proxy_container: str = "response-credential-proxy",
                 proxy_network: str = "cyber-response-agent_devcontainer_default",
                 es_image: str = DEFAULT_ES_IMAGE, cluster_name: str = "soc-playground",
                 certs_volume: str = "soc-playground_certs", repo_dir: str = "/srv/lab/frozen-cases",
                 readonly_user: str = "defender-readonly", poll_s: float = 5.0, ready_timeout_s: float = 300.0) -> None:
        self._run, self.context, self.proxy_context = run, context, proxy_context
        self.tenant_dir = Path(tenant_dir) if tenant_dir else None
        self.tenant_hosts, self.frozen_endpoint = list(tenant_hosts or ()), frozen_endpoint
        self._es = es
        self.audit_path, self.live_audit_path = audit_path, live_audit_path
        self.proxy_image, self.live_proxy_container = proxy_image, live_proxy_container
        self.proxy_network = proxy_network
        self.es_image, self.cluster_name = es_image, cluster_name
        self.certs_volume, self.repo_dir = certs_volume, repo_dir
        self.readonly_user = readonly_user
        self.poll_s, self.ready_timeout_s = poll_s, ready_timeout_s
        self._scratch: list[str] = []
        self._shim_ready = False
        self._stubs_loaded: str | None = None   # digest of what load_stubs was given, until teardown
        self._replicas: list[str] = []

    @classmethod
    def from_environment(cls) -> LabOps:
        """The operator's `V2_FROZEN_*` settings (runbook). Tenant host names come from the live
        lab tenant's `settings/systems/*/access.yaml` (`V2_FROZEN_TENANT_DIR`)."""
        env = os.environ
        return cls(
            tenant_dir=env.get("V2_FROZEN_TENANT_DIR"),
            frozen_endpoint=env.get("V2_FROZEN_ENDPOINT"), audit_path=env.get("V2_FROZEN_PROXY_AUDIT"),
            live_audit_path=env.get("V2_LIVE_PROXY_AUDIT"), proxy_context=env.get("V2_FROZEN_PROXY_CONTEXT"),
            es_image=env.get("V2_FROZEN_ES_IMAGE", DEFAULT_ES_IMAGE),
            cluster_name=env.get("V2_FROZEN_CLUSTER_NAME", "soc-playground"),
            certs_volume=env.get("V2_FROZEN_CERTS_VOLUME", "soc-playground_certs"),
            repo_dir=env.get("V2_FROZEN_REPO_DIR", "/srv/lab/frozen-cases"))

    # -- transport ---------------------------------------------------------------------------------

    def _exec(self, argv: list[str], check: bool = True, **kw: Any) -> Any:
        kw.setdefault("capture_output", True)
        if isinstance(kw.get("input"), str):
            kw.setdefault("text", True)
        proc = self._run(argv, **kw)
        if check and proc.returncode != 0:
            raise LabOpsError(f"{' '.join(argv[:6])}: rc={proc.returncode} {_text(proc.stderr).strip()}")
        return proc

    def _outer(self, *args: str, **kw: Any) -> Any:
        return self._exec(["docker", "--context", self.context, *args], **kw)

    def _engine(self, *args: str, **kw: Any) -> Any:
        """A command inside the engine container (`-i` when stdin is given)."""
        flags = ["-i"] if "input" in kw or "stdin" in kw else []
        return self._outer("exec", *flags, ENGINE, *args, **kw)

    def _inner(self, *args: str, **kw: Any) -> Any:
        """The engine's own docker, e.g. `_inner("run", ...)`."""
        return self._engine("docker", *args, **kw)

    def frozen_es(self) -> Any:
        """The frozen cluster through the chaos seam's `es_request` (`es=` replaces the real one)."""
        return self._es if self._es is not None else FrozenEs(self)

    def _live_es(self, method: str, path: str, body: Any = None) -> Any:
        from chaos.ctl import DockerExecSeam   # the live cluster's seam; the repo's own
        return DockerExecSeam(self._run).es_request(method, path, body)

    # -- the frozen engine ------------------------------------------------------------------------

    def _ensure_shim(self) -> None:
        if self._shim_ready:
            return
        self._outer("build", "-t", SHIM_IMAGE, str(SHIM_CONTEXT))
        self._outer("run", "--rm", "-v", "lab-clockshim:/out", SHIM_IMAGE, "cp", "/clockshim.so",
                    f"/out/{SHIM_FILE}")
        self._shim_ready = True

    def _ensure_image(self, image: str) -> None:
        if self._inner("image", "inspect", image, check=False).returncode == 0:
            return
        saved = self._outer("save", image).stdout
        self._inner("load", input=saved)

    def _ensure_current_image(self, image: str) -> None:
        """`image` in the engine as the lab server has it now: reloaded when the ids differ (a
        lab-built `:local` image changes under the same tag; an old copy would keep serving the
        old surface or argv)."""
        want = _text(self._outer("image", "inspect", "-f", "{{.Id}}", image).stdout).strip()
        have = self._inner("image", "inspect", "-f", "{{.Id}}", image, check=False)
        if have.returncode == 0 and _text(have.stdout).strip() == want:
            return
        saved = self._outer("save", image).stdout
        self._inner("load", input=saved)

    def ensure_engine(self) -> None:
        """The engine container, running, with the lab's certs, the repository, the shim and its
        state. A stopped engine (`inspect` prints `false`, rc 0: a reboot, a `docker stop`) is
        started again with its volumes, which hold the marker and the node's data."""
        state = self._outer("inspect", "-f", "{{.State.Running}}", ENGINE, check=False)
        if state.returncode == 0 and _text(state.stdout).strip() != "false":
            return
        if state.returncode == 0:
            self._outer("start", ENGINE)
        else:
            self._ensure_shim()
            self._outer("rm", "-f", ENGINE, check=False)
            ports = [a for p in FRONTEND_PORTS for a in ("-p", f"127.0.0.1:{FRONTEND_BASE + p}:{p}")]
            self._outer("run", "-d", "--privileged", "--name", ENGINE,
                        "-v", "lab-engine-docker:/var/lib/docker", "-v", f"lab-engine-state:{STATE_DIR}",
                        "-v", f"{self.certs_volume}:{CERTS_DIR}:ro", "-v", f"{self.repo_dir}:{REPO_DIR}:ro",
                        "-v", f"lab-clockshim:{SHIM_DIR}:ro", *ports,
                        ENGINE_IMAGE, "dockerd", "--host=unix:///var/run/docker.sock")
        deadline = time.monotonic() + 120
        while self._inner("version", check=False).returncode != 0:
            if time.monotonic() > deadline:
                raise LabOpsError("the frozen engine did not come up")
            time.sleep(2)
        self._inner("network", "create", ENGINE_NETWORK, check=False)
        self._engine("sh", "-c", f"mkdir -p {STATE_DIR}; [ -f {ES_ENV_FILE} ] || "
                     f"printf 'ELASTIC_PASSWORD=%s\\n' \"$(head -c 24 /dev/urandom | base64 | tr -d '/+=')\" "
                     f"> {ES_ENV_FILE}")

    def mount_node_cert(self) -> None:
        """The live node's certificate, from the lab's certs volume, is visible to the engine (and so
        to the frozen node it starts). It is mounted, never copied into a freeze part."""
        self.ensure_engine()
        self._engine("test", "-f", f"{CERTS_DIR}/elasticsearch/elasticsearch.crt")
        self._engine("test", "-f", f"{CERTS_DIR}/ca/ca.crt")

    def set_clock(self, as_of: Any) -> datetime:
        """Rewrite the node's clock offset to `as_of - now` in place (D15 revised): the running
        shim maps the file, so its next reading moves; a new file would never be read. One engine
        command reads the VPS's own clock, writes the offset from it and prints that instant W
        (r6.4.6), returned: the node reads `as_of + (now - W)`, and the agent's `--as-of-anchor W`
        makes its run clock the same function of wall time."""
        target = round(frozen_copy.utc(as_of).timestamp())
        out = self._engine("sh", "-c", f'mkdir -p {CLOCK_DIR} && now=$(date +%s) && '
                                       f'off=$(( $1 - now )) && [ ${{#off}} -lt {OFFSET_RECORD} ] && '
                                       f'printf "%23s\\n" "$off" 1<> {CLOCK_FILE} && echo "$now"',
                           "sh", str(target), text=True)
        try:
            return datetime.fromtimestamp(int(out.stdout.strip()), tz=UTC)
        except (ValueError, AttributeError) as exc:
            raise LabOpsError(f"the clock step printed no instant: {out.stdout!r}") from exc

    def _write_offset(self, offset: int | None) -> None:
        """The fixed record at byte 0 of CLOCK_FILE, opened without truncation (`1<>`, which also
        creates it). `None` creates the file at zero only if it is missing."""
        record = "%23s\\n"
        if offset is None:
            self._engine("sh", "-c", f'mkdir -p {CLOCK_DIR}; [ -f {CLOCK_FILE} ] || '
                                     f'printf "{record}" 0 1<> {CLOCK_FILE}')
            return
        text = str(int(offset))
        if len(text) >= OFFSET_RECORD:
            raise LabOpsError(f"clock offset {text} does not fit the {OFFSET_RECORD}-byte record")
        self._engine("sh", "-c", f'mkdir -p {CLOCK_DIR} && printf "{record}" "$1" 1<> {CLOCK_FILE}', "sh", text)

    def _start_node(self, as_of: Any = None) -> None:
        """A new node container on the `frozen-es-data` volume (as it is: a fresh restore removed it
        first). Its offset file holds `as_of - now` when the node starts."""
        self._ensure_image(self.es_image)
        self._inner("rm", "-f", ES_CONTAINER, check=False)
        certs = "certs/elasticsearch/elasticsearch"
        env = {"node.name": "es01", "cluster.name": self.cluster_name, "discovery.type": "single-node",
               "bootstrap.memory_lock": "false", "xpack.security.enabled": "true",
               "xpack.security.http.ssl.enabled": "true", "xpack.security.http.ssl.key": f"{certs}.key",
               "xpack.security.http.ssl.certificate": f"{certs}.crt",
               "xpack.security.http.ssl.certificate_authorities": "certs/ca/ca.crt",
               "xpack.security.transport.ssl.enabled": "true",
               "xpack.security.transport.ssl.key": f"{certs}.key",
               "xpack.security.transport.ssl.certificate": f"{certs}.crt",
               "xpack.security.transport.ssl.certificate_authorities": "certs/ca/ca.crt",
               "xpack.security.transport.ssl.verification_mode": "certificate",
               "path.repo": REPO_DIR, "ES_JAVA_OPTS": "-Xms2g -Xmx2g",
               "LD_PRELOAD": f"{SHIM_DIR}/{SHIM_FILE}",
               "V2_CLOCK_OFFSET_FILE": f"{NODE_CLOCK_DIR}/{Path(CLOCK_FILE).name}"}
        flags = [a for k, v in env.items() for a in ("-e", f"{k}={v}")]
        if as_of is None:
            self._write_offset(None)
        else:
            self.set_clock(as_of)
        self._inner("run", "-d", "--name", ES_CONTAINER, "--hostname", ES_CONTAINER,
                    "--network", ENGINE_NETWORK, "--env-file", ES_ENV_FILE, *flags,
                    "-v", f"{ES_DATA_VOLUME}:/usr/share/elasticsearch/data",
                    "-v", f"{CERTS_DIR}:/usr/share/elasticsearch/config/certs:ro",
                    "-v", f"{REPO_DIR}:{REPO_DIR}:ro", "-v", f"{SHIM_DIR}:{SHIM_DIR}:ro",
                    "-v", f"{CLOCK_DIR}:{NODE_CLOCK_DIR}:ro",
                    "--memory", "3g", self.es_image)

    def _node_state(self) -> str | None:
        """`true` / `false` (running or not) for the node container, None when there is none."""
        proc = self._inner("inspect", "-f", "{{.State.Running}}", ES_CONTAINER, check=False)
        return _text(proc.stdout).strip() if proc.returncode == 0 else None

    def node_exists(self) -> bool:
        """A frozen node container exists (running or stopped): there is a copy to keep."""
        self.ensure_engine()
        return self._node_state() is not None

    def ensure_node(self, as_of: Any = None) -> None:
        """The engine, and a frozen node running on the data it has. Idempotent: a running node is
        left alone; a stopped one is started again (the same container and data), a missing one is
        created; either way its clock reads `as_of` at its start (without `as_of` the offset file
        keeps what it holds). A teardown stops the node, so this comes before the first request to
        the cluster."""
        self.mount_node_cert()
        state = self._node_state()
        if state == "true":
            return
        if state is None:
            self._start_node(as_of)
            return
        if as_of is None:
            self._write_offset(None)
        else:
            self.set_clock(as_of)
        self._inner("start", ES_CONTAINER)

    def fresh_node(self, as_of: Any) -> None:
        """D25: discard the node container and its data volume and start a new, empty node whose
        clock reads `as_of` at its start. The marker, on the engine's state volume, is kept."""
        self.mount_node_cert()
        self._inner("rm", "-f", ES_CONTAINER, check=False)
        self._inner("volume", "rm", "-f", ES_DATA_VOLUME)
        self._start_node(as_of)

    # -- the copy-state marker (A4) ---------------------------------------------------------------

    def read_marker(self) -> dict | None:
        """The copy-state marker, or None (absent or unreadable: unknown is restored whole)."""
        self.ensure_engine()
        proc = self._engine("sh", "-c", f"cat {MARKER_FILE} 2>/dev/null; true", text=True)
        text = _text(proc.stdout).strip()
        try:
            return json.loads(text) if text else None
        except ValueError:
            return None   # unreadable is unknown, and unknown is restored whole

    def write_marker(self, marker: dict) -> None:
        self.ensure_engine()
        self._engine("sh", "-c", f"cat > {MARKER_FILE}.tmp && mv {MARKER_FILE}.tmp {MARKER_FILE}",
                     input=json.dumps(marker))

    # -- stubs ------------------------------------------------------------------------------------

    def load_stubs(self, parts: Any, as_of: Any, mutations: list | None = None) -> None:
        """Fresh stubs from the freeze's dump, clocks pinned at `as_of` (`V2_STUB_AS_OF`), the case's
        CMDB mutations applied at load."""
        parts = Path(parts)
        self.ensure_engine()
        stamp = frozen_copy.stamp(as_of)
        dump = (parts / STUBS_PART).read_bytes()
        self._stubs_loaded = hashlib.sha256(dump + json.dumps(mutations or [], sort_keys=True).encode()).hexdigest()
        self._engine("sh", "-c", f"rm -rf {SEED_DIR} && mkdir -p {SEED_DIR} && tar -x -C {SEED_DIR}",
                     input=dump)
        seeds = {"change-mgmt": ("stub-change-mgmt.yaml", "CHANGE_SEED_PATH"),
                 "ticket-server": ("stub-ticket-server.json", "TICKET_SEED_PATH"),
                 "threat-intel": ("stub-threat-intel.json", "TI_SEED_PATH")}
        for stub in STUBS:
            image = f"soc-playground/{stub}:local"
            self._ensure_image(image)
            self._inner("rm", "-f", stub, check=False)
            env = ["-e", f"V2_STUB_AS_OF={stamp}", "-e", "STANDING_REFRESH_SECONDS=0",
                   # Standing CRs were materialized into the dump; none is derived again.
                   "-e", "CHANGE_STANDING_PATH=/nonexistent"]
            mount: list[str] = []
            if stub in seeds:
                seed_file, seed_env = seeds[stub]
                env += ["-e", f"{seed_env}=/srv/seed/{seed_file}"]
                mount = ["-v", f"{SEED_DIR}:/srv/seed:ro"]
            self._inner("run", "-d", "--name", stub, "--hostname", stub, "--network", ENGINE_NETWORK,
                        *env, *mount, image)
        self._cmdb_overlays(mutations)

    _CMDB_SCRIPT = (
        "import json, sys, time, urllib.request\n"
        "for item in json.load(sys.stdin):\n"
        "    for _ in range(60):\n"
        "        try:\n"
        "            req = urllib.request.Request('http://127.0.0.1:8080/admin/overlay/' + item['host'],\n"
        "                data=json.dumps(item['patch']).encode(), method='POST',\n"
        "                headers={'Content-Type': 'application/json'})\n"
        "            urllib.request.urlopen(req, timeout=5).read(); break\n"
        "        except OSError:\n"
        "            time.sleep(1)\n"
        "    else:\n"
        "        sys.exit('cmdb overlay ' + item['host'] + ' not loaded')\n")

    def _cmdb_overlays(self, mutations: list | None) -> None:
        """The dump's overlays (none when no fault was active at capture), then the case's own."""
        steps = [{"host": host, "patch": patch}
                 for host, patch in _dump_overlays(self._engine("cat", f"{SEED_DIR}/stub-cmdb-overlays.json",
                                                                check=False))]
        steps += [{"kind": m["kind"], "host": m["host"], "patch": cmdb_patch(m)} for m in mutations or []
                  if m.get("kind") in ("field-flip", "phantom-host", "missing-host")]
        if steps:
            self._inner("exec", "-i", "cmdb", "python3", "-c", self._CMDB_SCRIPT, input=json.dumps(steps),
                        text=True)

    # -- credentials ------------------------------------------------------------------------------

    def current_password(self) -> str:
        """The read-only user's password as the lab stores it now (read at every launch)."""
        value = os.environ.get(READONLY_PASSWORD_ENV, "")
        if not value:
            raise LabOpsError(f"{READONLY_PASSWORD_ENV} is not set: the current password of the "
                              "lab's read-only Elasticsearch user (the lab .env's, as es-init uses it)")
        return value

    def _tenant_patterns(self) -> list[str]:
        if self.tenant_dir is None:
            raise NotConfigured("V2_FROZEN_TENANT_DIR is not set: the lab tenant's directory")
        return frozen_copy.tenant_patterns(self.tenant_dir / "settings")

    def create_readonly_user(self, password: str) -> None:
        """The proxy's read-only user in the frozen cluster: `read` on the configured patterns and
        `monitor`, with the current password. Created in the cluster, never in a freeze part."""
        es = self.frozen_es()
        es.es_request("PUT", f"/_security/role/{RO_ROLE}", {
            "cluster": ["monitor"],
            "indices": [{"names": self._tenant_patterns(), "privileges": ["read"]}]})
        es.es_request("PUT", f"/_security/user/{self.readonly_user}",
                      {"password": password, "roles": [RO_ROLE]})

    # -- the frozen proxy ------------------------------------------------------------------------

    def start_proxy(self) -> str:
        """Frontends for each declared port, then the product's proxy program in a second container
        on the deployment network. Returns the frozen proxy's own URL."""
        tenant_hosts = self.tenant_hosts or (declared_hosts(self.tenant_dir) if self.tenant_dir else [])
        if not (self.frozen_endpoint and self.audit_path and tenant_hosts):
            raise LabOpsError("the frozen proxy needs the tenant's hosts ($V2_FROZEN_TENANT_DIR), "
                              "frozen_endpoint and audit_path")
        if self.audit_path == self.live_audit_path:
            raise LabOpsError("the frozen proxy must not share the live proxy's audit file")
        self._frontends()
        address = self.frozen_endpoint.rsplit(":", 1)[0]
        hosts = [a for h in tenant_hosts for a in ("--add-host", f"{h}:{address}")]
        rewrite = ("import json, os; c = json.load(open('/proxy/config.json')); "
                   "c['audit_path'] = os.environ['V2_FROZEN_PROXY_AUDIT']; "
                   "json.dump(c, open('/tmp/frozen-proxy.json', 'w'))")
        python = "defender/.venv/bin/python"
        script = (f"{python} -c {shlex.quote(rewrite)} && "
                  f"exec {python} -m defender.credential_proxy")
        audit_dir = str(Path(self.audit_path).parent)
        argv = ["docker", *(["--context", self.proxy_context] if self.proxy_context else []),
                "rm", "-f", FROZEN_PROXY]
        self._exec(argv, check=False)
        argv = ["docker", *(["--context", self.proxy_context] if self.proxy_context else []),
                "run", "-d", "--name", FROZEN_PROXY, "--hostname", FROZEN_PROXY,
                "--network", self.proxy_network, "--volumes-from", self.live_proxy_container,
                "-v", f"frozen-proxy-audit:{audit_dir}", *hosts,
                "-e", "DEFENDER_CREDENTIAL_PROXY_CONFIG=/tmp/frozen-proxy.json",
                "-e", "DEFENDER_CREDENTIAL_PROXY_HOST=0.0.0.0",
                "-e", f"DEFENDER_CREDENTIAL_PROXY_PORT={PROXY_PORT}",
                "-e", f"V2_FROZEN_PROXY_AUDIT={self.audit_path}",
                self.proxy_image, "sh", "-c", script]
        self._exec(argv)
        return f"http://{FROZEN_PROXY}:{PROXY_PORT}"

    def _frontends(self) -> None:
        """The lab's edge program as the frozen copy's one frontend, every port of SURFACE, key
        check off (#1391 r6 L1): the same declared-surface rule as live. The per-port forwarders
        an older launcher started are removed first (they hold the same ports)."""
        self._ensure_current_image(EDGE_IMAGE)
        self._inner("rm", "-f", FRONTEND, *(f"frontend-{p}" for p in FRONTEND_PORTS), check=False)
        ports = [a for p in FRONTEND_PORTS for a in ("-p", f"{p}:{p}")]
        self._inner("run", "-d", "--name", FRONTEND, "--network", ENGINE_NETWORK, *ports,
                    EDGE_IMAGE, "--no-key-check")

    # -- host state (#1391 r6 O9) ------------------------------------------------------------------

    @staticmethod
    def frozen_hosts(freeze: dict) -> list[str]:
        """The hosts a freeze captured: any host one of its host parts names (`image-<host>.tar`,
        `proc-tree-<host>.txt`), never today's inventory. A host named by one part and missing
        another is then refused by `serve_hosts`, not silently left out."""
        hosts = set()
        for name in freeze["parts"]:
            if name.startswith("image-") and name.endswith(".tar"):
                hosts.add(name[len("image-"):-len(".tar")])
            elif name.startswith("proc-tree-") and name.endswith(".txt"):
                hosts.add(name[len("proc-tree-"):-len(".txt")])
        return sorted(hosts)

    @staticmethod
    def host_parts(host: str) -> dict[str, str]:
        """A host's parts: its image, its process tree and its volume copies (mount -> part)."""
        return {"image": f"image-{host}.tar", "tree": f"proc-tree-{host}.txt",
                **{mount: f"volume-{host}{mount.replace('/', '-')}.tar" for mount in HOST_VOLUMES}}

    def serve_hosts(self, parts: Any, freeze: dict) -> list[str]:
        """Inert replicas of the freeze's hosts and the endpoint-query service over them, in the
        engine. A freeze with no host image, or a host missing any of its parts, is refused: an
        empty host list would answer every host-state call with a quiet 404."""
        parts = Path(parts)
        hosts = self.frozen_hosts(freeze)
        if not hosts:
            raise LabOpsError("the freeze captured no host (no host image): host-state cannot be served")
        missing = [n for h in hosts for n in self.host_parts(h).values() if n not in freeze["parts"]]
        if missing:
            raise LabOpsError(f"the freeze lacks host parts {missing}: host-state cannot be served")
        self.ensure_engine()
        self._engine("sh", "-c", f"mkdir -p {HOST_SHIM_DIR} && cat > {HOST_SHIM_DIR}/ps && "
                                 f"chmod 0755 {HOST_SHIM_DIR}/ps", input=PS_SHIM.read_bytes())
        for host in hosts:
            self._replica(parts, freeze["parts"], host)
        self._start_query(hosts)
        return hosts

    @staticmethod
    def _key(sha: str) -> str:
        return str(sha)[:16]

    def _host_image(self, parts: Path, digests: dict, host: str) -> str:
        """The host's committed image in the engine, tagged by its part's digest. The saved image
        carries `local/<host>:latest` (every freeze's does), so it is retagged and that tag dropped:
        a tag alone would serve another freeze's host."""
        name = self.host_parts(host)["image"]
        tag = f"frozen-host/{host}:{self._key(digests[name])}"
        if self._inner("image", "inspect", tag, check=False).returncode != 0:
            with open(parts / name, "rb") as fh:
                self._inner("load", stdin=fh)
            self._inner("tag", f"local/{host}:latest", tag)
            self._inner("image", "rm", f"local/{host}:latest", check=False)
        return tag

    def _part_volume(self, parts: Path, name: str, digest: str, image: str) -> str:
        """A volume holding `name`'s content (a tar extracted; a file as `tree.txt`), filled once
        per part digest. `done` is written on the engine's state volume only after the fill, so an
        interrupted fill is redone, and no marker lands in the host's own files."""
        key = self._key(digest)
        volume, done = f"frozen-part-{key}", f"{HOST_PARTS_DIR}/{key}.done"
        if self._engine("test", "-f", done, check=False).returncode == 0:
            return volume
        self._inner("volume", "rm", "-f", volume, check=False)
        fill = (["--entrypoint", "tar", image, "-x", "-C", "/dst"] if name.endswith(".tar")
                else ["--entrypoint", "sh", image, "-c", "cat > /dst/tree.txt"])
        with open(parts / name, "rb") as fh:
            self._inner("run", "--rm", "-i", "--network", "none", "-v", f"{volume}:/dst", *fill, stdin=fh)
        self._engine("sh", "-c", f"mkdir -p {HOST_PARTS_DIR} && printf done > {done}")
        return volume

    def _replica(self, parts: Path, digests: dict, host: str) -> None:
        named = self.host_parts(host)
        image = self._host_image(parts, digests, host)
        tree = self._part_volume(parts, named["tree"], digests[named["tree"]], image)
        mounts = [a for mount in HOST_VOLUMES for a in (
            "-v", f"{self._part_volume(parts, named[mount], digests[named[mount]], image)}:{mount}:ro")]
        self._inner("rm", "-f", host, check=False)
        self._inner("run", "-d", "--name", host, "--hostname", host, "--network", "none", "--no-healthcheck",
                    "--entrypoint", "sleep", "-e", f"V2_PS_SHIM_TREE={REPLICA_TREE_DIR}/tree.txt",
                    "-v", f"{tree}:{REPLICA_TREE_DIR}:ro", *mounts,
                    "-v", f"{HOST_SHIM_DIR}/ps:/usr/local/bin/ps:ro", image, "infinity")
        self._replicas.append(host)

    def _start_query(self, hosts: list[str]) -> None:
        """The lab's endpoint-query service on the engine's daemon: the freeze's hosts, nothing
        inspectable (#1347's container-inspect gap; a replica's image name would tell the copy)."""
        self._ensure_current_image(QUERY_IMAGE)
        self._engine("sh", "-c", f"mkdir -p {QUERY_DIR} && cat > {QUERY_DIR}/hosts.txt && "
                                 f"printf '' > {QUERY_DIR}/inspectable.txt", input="\n".join(hosts) + "\n")
        self._inner("rm", "-f", HOST_STATE_SERVICE, check=False)
        self._inner("run", "-d", "--name", HOST_STATE_SERVICE, "--hostname", HOST_STATE_SERVICE,
                    "--network", ENGINE_NETWORK, "-v", "/var/run/docker.sock:/var/run/docker.sock",
                    "-v", f"{QUERY_DIR}:/etc/endpoint-query:ro", QUERY_IMAGE,
                    "--hosts", "/etc/endpoint-query/hosts.txt", "--inspectable", "/etc/endpoint-query/inspectable.txt")

    def purge_host_cache(self, freeze: dict) -> None:
        """Remove a freeze's cached host images and extracted parts from the engine (no automatic
        eviction). A part another freeze shares (same digest) goes too; it is refilled on demand."""
        self.ensure_engine()
        for host in self.frozen_hosts(freeze):
            for kind, name in self.host_parts(host).items():
                digest = freeze["parts"].get(name)
                if digest is None:
                    continue
                key = self._key(digest)
                if kind == "image":
                    self._inner("image", "rm", f"frozen-host/{host}:{key}", check=False)
                else:
                    self._inner("volume", "rm", "-f", f"frozen-part-{key}", check=False)
                    self._engine("rm", "-f", f"{HOST_PARTS_DIR}/{key}.done", check=False)

    def content_digest(self, indices: list[str]) -> str:
        """sha256 over every document of the named `indices` (the ones the overlays touched) in the
        frozen cluster (index, id, version, source) and over the stubs: what they were loaded with and
        what each now holds. An in-place edit of a touched index or a stale stub changes it (A1); an
        untouched index is never read, its count is compared instead (live: reading all of them took
        ~18 h). A named index the cluster does not hold is refused."""
        if self._stubs_loaded is None:
            raise LabOpsError("content_digest asked before the stubs were loaded")
        es = self.frozen_es()
        names = sorted(set(indices))
        held = set(frozen_copy.held_indices(es))
        if missing := [n for n in names if n not in held]:
            raise LabOpsError(f"content_digest: the frozen cluster holds no index {missing}")
        digest = hashlib.sha256()
        for name in names:
            docs = sorted(self._document_digests(es, name))
            digest.update(json.dumps([name, docs], separators=(",", ":")).encode())
        digest.update(self._stubs_loaded.encode())
        for stub, path in STUB_STATE.items():
            digest.update(self._stub_text(stub, path).encode())
        return digest.hexdigest()

    @staticmethod
    def _document_digests(es: Any, name: str) -> list[str]:
        """sha256 of each document of the index `name`, read through one fixed view (r6.4.6)."""
        return [hashlib.sha256(json.dumps([h["_index"], h["_id"], h.get("_version"), h["_source"]], sort_keys=True,
                                          separators=(",", ":")).encode()).hexdigest()
                for h in frozen_copy.walk(es, name, {"match_all": {}}, source=True, version=True)]

    def teardown(self) -> None:
        """Stop the proxy, the frontend, the stubs, the replicas and the endpoint-query service; the
        frozen cluster and its data stay, and so do the cached host images and parts."""
        self._exec(["docker", *(["--context", self.proxy_context] if self.proxy_context else []),
                    "rm", "-f", FROZEN_PROXY], check=False)
        names = [FRONTEND, *(f"frontend-{p}" for p in FRONTEND_PORTS), *STUBS, HOST_STATE_SERVICE,
                 *self._replicas]
        self._replicas = []
        self._inner("rm", "-f", *names, check=False)
        self._inner("stop", ES_CONTAINER, check=False)
        self._stubs_loaded = None
        for path in self._scratch:
            _rmtree(path)
        self._scratch = []

    # -- capture (O1) -----------------------------------------------------------------------------

    def hosts(self) -> list[str]:
        inventory = yaml.safe_load((PLAYGROUND / "hosts" / "inventory.yaml").read_text())
        return [h["name"] for h in inventory["hosts"]]

    def active_faults(self) -> list[str]:
        """Profiles with a chaos ledger record still on the stack; unreadable files count as one."""
        from chaos import ledger
        records, malformed = ledger.read_ledger(PLAYGROUND / "chaos" / "ledger")
        return [str(r.get("profile_id", r.get("ledger_ref"))) for r in records] + sorted(malformed)

    def hold_pickups(self) -> None:
        """Stop the alert-ticket watcher, so no alert of the batch gets a ticket or a live run.
        Any other live pickup of the deployment is the operator's to stop first (runbook)."""
        self._outer("stop", WATCHER)

    def release_pickups(self) -> None:
        self._outer("start", WATCHER)

    def scenario_ids(self) -> set[str]:
        """The attack catalog's scenario ids, as `fire` reads them."""
        return set(_load_module("attack_runner", PLAYGROUND / "attacks" / "runner.py").load_catalog())

    def fire(self, scenario: str, lock_token: str) -> dict:
        runner = _load_module("attack_runner", PLAYGROUND / "attacks" / "runner.py")
        from chaos import lock
        runs_dir = _configured_dir("V2_ATTACK_RUNS_DIR", "the attack runs would land in the repository")
        catalog = runner.load_catalog()
        run_id, _, _ = runner.run_scenario(catalog[scenario], 42, {}, False, runs_dir=runs_dir,
                                           lock_store=lock.DockerLockStore(run=self._run, context=self.context),
                                           lock_token=lock_token)
        return {"run_id": run_id}

    def proc_tree(self, dest: Path) -> list[str]:
        """Each role host's process tree as the proc-tree verb reads it (D6)."""
        Path(dest).mkdir(parents=True, exist_ok=True)
        names = []
        for host in self.hosts():
            name = f"proc-tree-{host}.txt"
            (Path(dest) / name).write_bytes(self._outer("exec", host, *PS_ARGV).stdout)
            names.append(name)
        return names

    def stub_dumps(self, dest: Path) -> list[str]:
        """Each stub's state in the shape its seed loader reads, in one tar."""
        Path(dest).mkdir(parents=True, exist_ok=True)
        files = {
            "stub-change-mgmt.yaml": yaml.safe_dump(self._stub_get("change-mgmt", "/changes")["changes"],
                                                    sort_keys=False),
            "stub-ticket-server.json": json.dumps(self._stub_get("ticket-server", "/tickets")["tickets"], indent=1),
            "stub-threat-intel.json": json.dumps(self._stub_get("threat-intel", "/indicators")["indicators"], indent=1)}
        overlays = {}
        listed = [h["name"] for h in self._stub_get("cmdb", "/hosts")["hosts"]]
        for name in sorted(set(listed) | set(self.hosts())):
            overlay = self._stub_get("cmdb", f"/admin/overlay/{name}").get("overlay")
            if overlay is not None:
                overlays[name] = overlay
        files["stub-cmdb-overlays.json"] = json.dumps(overlays, indent=1)
        _write_tar(Path(dest) / STUBS_PART, {n: t.encode() for n, t in files.items()})
        return [STUBS_PART]

    def detection_rules(self, dest: Path) -> list[str]:
        """The rules the installer deploys (`detection-rules/*.json`, its source of truth), as of T."""
        Path(dest).mkdir(parents=True, exist_ok=True)
        rules = sorted((PLAYGROUND / "detection-rules").glob("*.json"))
        _write_tar(Path(dest) / RULES_PART, {p.name: p.read_bytes() for p in rules})
        return [RULES_PART]

    def commit_hosts(self, dest: Path) -> list[str]:
        """Commit each role host (the commit pauses it) and save the image."""
        Path(dest).mkdir(parents=True, exist_ok=True)
        names = []
        for host in self.hosts():
            tag = f"local/{host}:latest"
            self._outer("commit", "--pause=true", host, tag)
            try:
                names.append(self._save_image(tag, Path(dest) / f"image-{host}.tar"))
            finally:
                self._outer("image", "rm", tag, check=False)
        return names

    def copy_volumes(self, dest: Path) -> list[str]:
        """/var/log and /var/lib/elastic-agent of each role host, through a throwaway container that
        mounts the host's volumes read-only, with the host paused for its copy (a running agent
        rewrites its state as tar reads it: live check, 2026-11-10). Certs and tokens live elsewhere
        and are not copied."""
        Path(dest).mkdir(parents=True, exist_ok=True)
        names = []
        for host in self.hosts():
            image = self._outer("inspect", "--format", "{{.Config.Image}}", host, text=True).stdout.strip()
            self._outer("pause", host)
            try:
                for mount in HOST_VOLUMES:
                    name = f"volume-{host}{mount.replace('/', '-')}.tar"
                    with open(Path(dest) / name, "wb") as fh:
                        self._outer("run", "--rm", "--volumes-from", f"{host}:ro", "--entrypoint", "tar",
                                    "--network", "none", image, "-C", mount, "-cf", "-", ".",
                                    capture_output=False, stdout=fh, stderr=subprocess.PIPE)
                    names.append(name)
            finally:
                self._outer("unpause", host, check=False)
        return names

    def verify_restore(self, repository: str, snapshot: str) -> dict[str, Any]:
        """Restore the snapshot into a scratch cluster on the lab server and return what the
        snapshot itself holds (r6.4.6): `{"indices": {name: top-level _count}, "data_streams":
        {stream: [members]}}`, the streams the snapshot names with the members the restore gave them. Indices the scratch node makes for itself are not the snapshot's, so they never
        enter a freeze. The scratch cluster is removed either way."""
        name = "lab-verify-es"
        self._outer("rm", "-f", "-v", name, check=False)
        self._outer("run", "-d", "--name", name, "-e", "discovery.type=single-node",
                    "-e", "xpack.security.enabled=false", "-e", f"path.repo={REPO_DIR}",
                    "-e", "ES_JAVA_OPTS=-Xms1g -Xmx1g", "-v", f"{self.repo_dir}:{REPO_DIR}:ro", self.es_image)
        try:
            def call(method: str, path: str, body: Any = None) -> Any:
                args = ["-s", "-f", "-X", method, "-H", "Content-Type: application/json"]
                if body is not None:
                    args += ["--data-binary", "@-"]
                proc = self._outer("exec", *(["-i"] if body is not None else []), name, "curl", *args,
                                   f"http://localhost:9200{path}", text=True,
                                   **({"input": json.dumps(body)} if body is not None else {}))
                return json.loads(proc.stdout or "{}")

            deadline = time.monotonic() + 180
            while True:
                try:
                    call("GET", "/_cluster/health")
                    break
                except LabOpsError:
                    if time.monotonic() > deadline:
                        raise LabOpsError("the scratch cluster did not come up") from None
                    time.sleep(3)
            call("PUT", f"/_snapshot/{repository}", {"type": "fs", "settings": {"location": REPO_DIR, "readonly": True}})
            call("POST", f"/_snapshot/{repository}/{snapshot}/_restore?wait_for_completion=true",
                 {"include_global_state": False})
            call("POST", "/_refresh?expand_wildcards=all")
            held = call("GET", f"/_snapshot/{repository}/{snapshot}")["snapshots"][0]
            streams = sorted(held.get("data_streams") or [])
            members = frozen_copy.stream_members(
                call("GET", f"/_data_stream/{','.join(streams)}?expand_wildcards=all")) if streams else {}
            # Top-level documents (`_count`), the count every later check compares: `docs.count`
            # also counts the hidden documents of nested fields (r6.4.4).
            return {"indices": {n: int(call("GET", f"/{n}/_count")["count"]) for n in sorted(held["indices"])},
                    "data_streams": {s: members.get(s, []) for s in streams}}
        finally:
            self._outer("rm", "-f", "-v", name, check=False)

    # -- make-a-case (O13) ------------------------------------------------------------------------

    def snapshot_alerts(self, freeze_dir: Path) -> list[dict]:
        """Alerts stamped up to T: read from the live alerts index (it only grows), so a workflow
        status changed after T shows here; make-a-case re-reads the alert in the frozen copy."""
        freeze = yaml.safe_load((Path(freeze_dir) / "freeze.yaml").read_text())
        alerts_pattern = freeze["patterns"][1]
        fields = ["@timestamp", "kibana.alert.uuid", "kibana.alert.workflow_status"]
        out: list[dict] = []
        after = None
        while True:
            body: dict[str, Any] = {"size": 1000, "_source": fields,
                                    "sort": [{"@timestamp": "asc"}, {"kibana.alert.uuid": "asc"}],
                                    "query": {"range": {"@timestamp": {"lte": frozen_copy.stamp(freeze["T"])}}}}
            if after:
                body["search_after"] = after
            hits = self._live_es("POST", f"/{alerts_pattern}/_search?expand_wildcards=open,hidden", body)["hits"]["hits"]
            out += [h["_source"] for h in hits]
            if len(hits) < 1000:
                return out
            after = hits[-1]["sort"]

    def live_run_alerts(self) -> set[str]:
        """Alerts a defender run has been started for: the `alert.json` of every run directory.
        An unset runs directory is a refusal: an empty set would exclude nothing."""
        runs_dir = _configured_dir("V2_RUNS_DIR", "the live runs cannot be excluded")
        found: set[str] = set()
        for path in runs_dir.rglob("alert.json"):
            try:
                doc = json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            if (uuid := frozen_copy.alert_uuid(doc)) is not None:
                found.add(uuid)
        return found

    def ticketed_alerts(self) -> set[str]:
        """Alerts that had a ticket at T: the ticket ids in each freeze's stub dump (the watcher keys
        a ticket by its alert's uuid). An unset parts directory is a refusal, not an empty set."""
        parts_dir = _configured_dir("V2_FROZEN_PARTS_DIR", "the ticketed alerts cannot be excluded")
        found: set[str] = set()
        for tarball in parts_dir.glob(f"*/{STUBS_PART}"):
            with tarfile.open(tarball) as tar:
                member = tar.extractfile("stub-ticket-server.json")
                for ticket in json.load(member) if member else []:
                    found.add(str(ticket.get("id") or ticket.get("key")))
        return found

    def freeze_rules(self, freeze_dir: Path) -> Path:
        """The detection rules as of T, unpacked into a directory removed at teardown (the caller
        may remove it sooner; a failed unpack removes it at once)."""
        parts_dir = _configured_dir("V2_FROZEN_PARTS_DIR", "the rules at T cannot be read")
        target = Path(tempfile.mkdtemp(prefix="rules-at-T."))
        self._scratch.append(str(target))
        try:
            with tarfile.open(parts_dir / Path(freeze_dir).name / RULES_PART) as tar:
                tar.extractall(target, filter="data")
        except BaseException:
            _rmtree(str(target))
            raise
        return target

    # -- helpers ----------------------------------------------------------------------------------

    _GET = ("import sys, urllib.request\n"
            "sys.stdout.write(urllib.request.urlopen('http://127.0.0.1:8080' + sys.argv[1], "
            "timeout=10).read().decode())\n")

    def _stub_get(self, stub: str, path: str) -> Any:
        """A stub of the LIVE lab, read inside its own container (as the chaos control does)."""
        return json.loads(self._outer("exec", stub, "python3", "-c", self._GET, path, text=True).stdout)

    def _stub_text(self, stub: str, path: str) -> str:
        """The same read of a FROZEN stub, inside the engine."""
        return _text(self._inner("exec", stub, "python3", "-c", self._GET, path, text=True).stdout)

    def _save_image(self, image: str, path: Path) -> str:
        with open(path, "wb") as fh:
            self._outer("save", image, capture_output=False, stdout=fh, stderr=subprocess.PIPE)
        return path.name




def _dump_overlays(proc: Any) -> list[tuple[str, dict]]:
    if proc.returncode != 0 or not _text(proc.stdout).strip():
        return []
    return sorted(json.loads(_text(proc.stdout)).items())


def _write_tar(path: Path, members: dict[str, bytes]) -> None:
    with tarfile.open(path, "w") as tar:
        for name, data in sorted(members.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mtime = len(data), 0
            tar.addfile(info, io.BytesIO(data))


def _rmtree(path: str) -> None:
    import shutil
    shutil.rmtree(path, ignore_errors=True)


def _load_module(name: str, path: Path) -> Any:
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _configured_dir(variable: str, why: str) -> Path:
    """The directory `$variable` names; unset or not a directory is a refusal, never an empty answer."""
    value = os.environ.get(variable)
    if not value:
        raise NotConfigured(f"{variable} is not set: {why}")
    path = Path(value)
    if not path.is_dir():
        raise NotConfigured(f"{variable} ({path}) is not a directory: {why}")
    return path


def declared_hosts(tenant_dir: Path) -> list[str]:
    """The host names a lab tenant declares in `settings/systems/*/access.yaml` (`base:`). A tenant
    that declares an IP literal cannot be resolved to the frozen copy (#1391 O6): refused."""
    import ipaddress
    names: list[str] = []
    for path in sorted(Path(tenant_dir).glob("settings/systems/*/access.yaml")):
        base = (yaml.safe_load(path.read_text()) or {}).get("base")
        host = urlsplit(str(base)).hostname if base else None
        if not host:
            continue
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if host not in names:
                names.append(host)
        else:
            raise LabOpsError(f"{path}: base names an IP literal ({host}); a frozen run needs host names")
    return names
