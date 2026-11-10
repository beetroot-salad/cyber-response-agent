"""#1347 r6.4 O1/O10/A5/A9: one capture per freeze, all-or-nothing, under the capture lock.

Entry point bound by this contract: `playground-v2/scripts/capture_case.py::capture(freeze_dir,
*, T, scenarios, repository, tenant_settings, ops, es, lock_store, parts_dir, clock, captured_by)`.
`tenant_settings` is the lab tenant's `settings/` directory: capture reads the events and alerts
patterns from its `systems/elastic/config.env` (`ELASTIC_EVENTS_INDEX`, `ELASTIC_ALERTS_INDEX`, D24)
and records them in `freeze.yaml` as `patterns: [events, alerts]`; there is no `patterns` parameter.
`freeze_dir` is `held_out/freezes/<freeze-id>/` (the freeze id is its name); parts go under
`parts_dir/<freeze-id>/`; writes `freeze_dir/freeze.yaml`. `es` is the LIVE cluster through
the chaos seam's `es_request(method, path, body=None)`. `ops` is the lab layer, `lab_ops.LabOps`:
active_faults() -> list; hold_pickups(); release_pickups() (AT2: the alert-ticket
watcher only, not every live defender pickup); fire(scenario, lock_token); proc_tree(dest), stub_dumps(dest),
commit_hosts(dest), copy_volumes(dest), detection_rules(dest) (the rules installed at T) ->
part names written under dest; verify_restore(repository, snapshot) -> {index: count} (a scratch
cluster). The lock is `chaos.lock` (`take/release`, `CAPTURE = "capture"`) on `lock_store`.
The operator registered `repository` once; capture only verifies it (GET `/_snapshot/<repo>` or
POST `/_snapshot/<repo>/_verify`) and never registers it.

r6.4.3 settlements (C-rig covers capture): these tests construct the REAL `lab_ops.LabOps` and fake only its
outer edge, as the make-a-case and launcher tests do (`_rig_docker.RigDocker`):

* docker, through `run=` (and `subprocess.run` itself, for the attack runner `fire` loads, which calls docker
  directly): the live lab on `soc-playground` holds the role hosts of the committed `hosts/inventory.yaml` (each
  answering `ps` with its own process tree and holding its own `/var/log` and `/var/lib/elastic-agent`
  volumes), the live stubs (each serving its own state), the alert-ticket watcher, and the live Elasticsearch
  container, which holds `chaos.lock`'s store and answers the chaos seam's curl from the live cluster;
* the live cluster (`rig.es`, a `FakeES` whose repository holds `rig.snapshots`), reached through the real
  chaos seam (`chaos.ctl.DockerExecSeam` over the rig docker);
* the scratch cluster the verification restore starts on the lab server (`lab-verify-es`), answering from
  what the repository holds;
* the lock store is `chaos.lock.DockerLockStore` over the rig docker: the same records the attack runner
  checks the token against;
* the chaos ledger `active_faults` reads (redirected to a scratch ledger per test) and the attack runner's
  sleeps (not slept). The committed inventory, detection rules and attack catalog are read as they are.

Bound by the r6.4.3 review repair: `LabOps.fire` writes the attack runner's run records into the directory
`$V2_ATTACK_RUNS_DIR` names (read when it fires), never into the repository's `attacks/runs/`.

`fail_at` makes the docker calls of one capture step fail (exit 125): `hold_pickups` (stopping the watcher),
`fire` (every command a role host runs for the batch), `proc_tree`, `stub_dumps`, `commit_hosts`,
`copy_volumes`, `verify_restore` (starting the scratch cluster); `snapshot` fails the snapshot request.
`detection_rules` has no outer edge (it reads the committed rules): the rig observes the real method and, for
that one fault, fails it after it wrote its part.
"""
from __future__ import annotations

import copy
import importlib.util
import inspect
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from _lab_fakes import CONTEXT, LAB_OPS, RULES_PART, FakeClock, FakeES, Journal, config_env, instant, load_script, sha
from _rig_docker import RigDocker
from chaos import ledger, lock
from chaos.ctl import DockerExecSeam

CAPTURE = Path(__file__).resolve().parents[1] / "capture_case.py"
PLAYGROUND = Path(__file__).resolve().parents[2]
FREEZE_ID = "f-2026-10-20"
T = instant("2026-10-20T09:00:00Z")
MAX_AGE = timedelta(hours=6)
PATTERNS = ["logs-*", ".internal.alerts-security.alerts-*"]   # as the lab tenant configures them (not a built-in default)
REPO = "frozen-cases"
SNAP_UUID = "dGhlLXNuYXBzaG90LXV1aWQ"
COUNTS = {"logs-system.auth-2026.10": 120_400, ".internal.alerts-security.alerts-default-000001": 37}
CATALOG = {s["id"]: s for s in yaml.safe_load((PLAYGROUND / "attacks" / "catalog.yaml").read_text())["scenarios"]}
SCENARIOS = ["ssh-brute-force-canary", "web-path-scan", "persistence-authorized-keys"]   # from the committed catalog
HOSTS = [h["name"] for h in yaml.safe_load((PLAYGROUND / "hosts" / "inventory.yaml").read_text())["hosts"]]
RULE_FILES = {p.name: p.read_bytes() for p in sorted((PLAYGROUND / "detection-rules").glob("*.json"))}
HOST_MOUNTS = ("/var/log", "/var/lib/elastic-agent")
WATCHER = "alert-ticket-watcher"
VERIFY = "lab-verify-es"
LOCK_FILE = f"{lock.LOCK_DIR}/{lock.CAPTURE}"
STUBS = {
    "change-mgmt": {"/changes": {"changes": [{"id": "CHG-7", "status": "approved", "hosts": ["web-1"]}]}},
    "ticket-server": {"/tickets": {"tickets": [{"id": "alert-uuid-1", "status": "open"}]}},
    "threat-intel": {"/indicators": {"indicators": [{"indicator": "203.0.113.9", "type": "ipv4"}]}},
    "cmdb": {"/hosts": {"hosts": [{"name": h} for h in HOSTS]},
             f"/admin/overlay/{HOSTS[0]}": {"overlay": {"owner": "sre.alice", "status": "maintenance"}},
             **{f"/admin/overlay/{h}": {} for h in HOSTS[1:]}},
}
PART_STEPS = ["proc_tree", "stub_dumps", "commit_hosts", "copy_volumes", "detection_rules"]
SNAP_URL = re.compile(rf"^/_snapshot/{REPO}/(?P<name>[^_/][^/]*)$")
REPO_RUNS = PLAYGROUND / "attacks" / "runs"


def _module():
    spec = importlib.util.spec_from_file_location("capture_1347", CAPTURE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ps_of(host: str) -> bytes:
    return (f"  PID  PPID USER     STAT     ELAPSED CMD\n    1     0 root     Ss    3-02:11:09 /sbin/init\n"
            f"  412     1 root     Ss    3-02:10:58 /usr/sbin/sshd -D [{host}]\n").encode()


def volume_files(host: str, mount: str) -> dict[str, bytes]:
    if mount == "/var/log":
        return {"auth.log": f"Oct 20 08:59:01 {host} sshd[412]: Accepted publickey\n".encode(),
                "nginx/access.log": f"{host} GET / 200\n".encode()}
    return {"state.enc": f"agent state of {host}".encode(), "data/registry.json": b'{"v": 1}'}


def _template(cmd: str) -> re.Pattern:
    return re.compile(".*?".join(re.escape(piece) for piece in re.split(r"\$\{\w+\}", cmd)), re.S)


def scenario_of(command: str) -> str | None:
    """The scenario of the committed catalog whose step renders to `command` (one of SCENARIOS)."""
    found = {sid for sid in SCENARIOS for step in CATALOG[sid]["steps"] if _template(step["cmd"]).fullmatch(command)}
    assert len(found) <= 1, (command, found)
    return next(iter(found), None)


def commands_of(scenario: str) -> int:
    """How many commands one firing of `scenario` runs (each step, repeated as the catalog says)."""
    sc = CATALOG[scenario]
    return sum(int(sc.get("default_intensity", 1)) if st.get("repeat", 1) == "${intensity}" else int(st.get("repeat", 1))
               for st in sc["steps"])


def tar_members(data: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        return {m.name.removeprefix("./"): tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}


_EDGES: dict = {}


@pytest.fixture(autouse=True)
def _lab_edges(monkeypatch, tmp_path):
    """The edges no `run=` reaches: the attack runner's own `subprocess.run` (pointed at the rig's docker by each
    Rig), its sleeps, the chaos ledger (a scratch one), and the runs directory (`V2_ATTACK_RUNS_DIR`, a scratch
    one). Run records a `fire` still put under the repository's `attacks/runs/` are removed by the run ids `fire`
    returned (never by listing that shared directory)."""
    real_read, real_sleep = ledger.read_ledger, time.sleep
    scratch = tmp_path / "scratch-ledger"
    scratch.mkdir()
    lab_ledger = (PLAYGROUND / "chaos" / "ledger").resolve()

    def read_ledger(path):
        return real_read(scratch if Path(path).resolve() == lab_ledger else path)

    def sleep(seconds):
        if sys._getframe(1).f_globals.get("__name__") != "attack_runner":
            real_sleep(seconds)

    def no_docker(argv, *a, **kw):
        raise AssertionError(f"a command outside the rig: {argv}")

    real_run = subprocess.run
    monkeypatch.setattr(ledger, "read_ledger", read_ledger)
    monkeypatch.setattr(time, "sleep", sleep)
    monkeypatch.setattr(subprocess, "run", no_docker)
    attack_runs = tmp_path / "attack-runs"
    attack_runs.mkdir()
    monkeypatch.setenv("V2_ATTACK_RUNS_DIR", str(attack_runs))
    returned: list[str] = []
    _EDGES.update(monkeypatch=monkeypatch, ledger=scratch, real_run=real_run, run_ids=returned,
                  attack_runs=attack_runs)
    yield
    _EDGES.clear()
    for run_id in returned:
        if run_id and Path(run_id).name == run_id:
            shutil.rmtree(REPO_RUNS / run_id, ignore_errors=True)


class ScratchCluster:
    """The verification restore's scratch cluster: it restores from what the repository holds (`rig.snapshots`,
    with `rig.contents` as each snapshot's indices and counts) and answers `_cat/indices` from what it restored."""

    def __init__(self, rig: "Rig") -> None:
        self.rig, self.repos, self.indices, self.down_requests = rig, {}, {}, []

    def es_request(self, method: str, path: str, body=None):
        self.rig.journal.append(("verify.es", (method, path)))
        p = path.split("?", 1)[0].rstrip("/")
        if p == "/_cluster/health":
            return {"status": "green"}
        m = re.fullmatch(r"/_snapshot/([^/]+)", p)
        if m and method == "PUT":
            self.repos[m[1]] = copy.deepcopy(body)
            return {"acknowledged": True}
        m = re.fullmatch(r"/_snapshot/([^/]+)/([^/]+)/_restore", p)
        if m and method == "POST":
            if m[1] not in self.repos:
                raise RuntimeError(f"repository_missing_exception [{m[1]}]")
            if m[1] != REPO or m[2] not in self.rig.snapshots:
                raise RuntimeError(f"snapshot_restore_exception [{m[1]}:{m[2]}] snapshot does not exist")
            self.rig.restores.append((m[1], m[2]))
            self.indices.update(self.rig.contents.get(m[2], {}))
            return {"accepted": True}
        if p in ("/_refresh", "/_all/_refresh", "/*/_refresh"):
            return {"_shards": {"failed": 0}}
        if p == "/_cat/indices" and method == "GET":
            return [{"index": i, "docs.count": str(n)} for i, n in sorted(self.indices.items())]
        raise AssertionError(f"the scratch cluster does not model {method} {path}")


class CaptureDocker(RigDocker):
    """The rig docker, naming each call by the capture step it belongs to (journal entry, lock and watcher state
    at the call, clock) and failing the calls of `rig.fail_at`'s step."""

    def __init__(self, rig: "Rig", **kw) -> None:
        super().__init__(**kw)
        self.rig = rig

    def __call__(self, argv, **kw):
        argv = [str(a) for a in argv]
        r = self.rig
        step = r.classify(argv)
        if step is None:
            return super().__call__(argv, **kw)
        held, watching = r.lock_held(), r.watcher_running()
        r.journal.append((step, argv[3:8]))
        r.held_at.setdefault(step, []).append(held)
        r.watching_at.setdefault(step, []).append(watching)
        r.at.setdefault(step, []).append(r.clock.last)
        if step == r.fail_at:
            text = kw.get("text") or kw.get("universal_newlines")
            done = subprocess.CompletedProcess(argv, 125, stdout="" if text else b"",
                                               stderr=f"injected: {step} failed" if text else f"injected: {step} failed".encode())
            if kw.get("check"):
                raise subprocess.CalledProcessError(125, argv, output=done.stdout, stderr=done.stderr)
            return done
        done = super().__call__(argv, **kw)
        r.calls.append({"step": step, "argv": argv, "clock": r.clock.last, "held": held, "held_after": r.lock_held(),
                        "watching": watching, "rc": done.returncode})
        return done


class Rig:
    """`occupied` models a repository that already holds a snapshot before capture starts: "freeze-id"
    under the freeze's own id (a reused freeze id), "other-name" under `older`, "asked-name" under whatever
    name capture asks for first (seeded at that request, for a capture that names its snapshot otherwise).
    Creating a snapshot under a taken name fails as Elasticsearch fails it. `clock_step=0` makes `now()` stand still
    until slept, for exact-boundary tests. `faults` are chaos ledger records still on the stack (profile ids)."""

    def __init__(self, tmp_path: Path, fail_at: str | None = None, faults: list | None = None,
                 state: str = "SUCCESS", repository_registered: bool = True, *, t=T, scenarios=None,
                 clock_start=None, clock_step: float = 1, occupied: str | None = None,
                 patterns: list[str] = PATTERNS):
        self.t, self.scenarios = t, SCENARIOS if scenarios is None else scenarios
        self.fail_at = fail_at
        self.journal = Journal()
        self.clock = FakeClock(self.journal, clock_start or T - MAX_AGE - timedelta(minutes=5), clock_step)
        self.tenant_settings = tmp_path / "tenant" / "settings"
        env = self.tenant_settings / "systems" / "elastic" / "config.env"
        env.parent.mkdir(parents=True)
        env.write_text(config_env(*patterns))
        self.patterns = list(patterns)
        self.held_at: dict[str, list[bool]] = {}
        self.watching_at: dict[str, list[bool]] = {}
        self.at: dict[str, list] = {}
        self.calls: list[dict] = []
        self.snapshots: dict[str, dict] = {}  # what the live cluster's repository holds
        self.contents: dict[str, dict] = {}   # each snapshot's indices and their counts
        self.preexisting: dict[str, dict] = {}   # what it held before capture touched it
        self.restores: list[tuple[str, str]] = []
        self.occupied = occupied
        if occupied == "other-name":
            self._seed("older")
        if occupied == "freeze-id":
            self._seed(FREEZE_ID)
        for i, profile in enumerate(faults or []):
            ledger.write_record(_EDGES["ledger"], {"ledger_ref": f"fault-{i}", "profile_id": profile,
                                                    "applied_at": "2026-10-20T01:00:00Z"})

        def route(method, path, body):
            m = SNAP_URL.match(path)
            if m and occupied == "asked-name" and not self.preexisting:
                self._seed(m["name"])
            if method in ("PUT", "POST") and m:
                self.held_at.setdefault("snapshot", []).append(self.lock_held())
                self.watching_at.setdefault("snapshot", []).append(self.watcher_running())
                self.at.setdefault("snapshot", []).append(self.clock.last)
                if fail_at == "snapshot":
                    raise RuntimeError("snapshot failed")
                if m["name"] in self.snapshots:
                    raise RuntimeError(f"invalid_snapshot_name_exception: [{REPO}:{m['name']}] Invalid "
                                       f"snapshot name [{m['name']}], snapshot with the same name already exists")
                self.snapshots[m["name"]] = {"snapshot": m["name"], "uuid": SNAP_UUID,
                                             "state": state, "indices": list(COUNTS)}
                self.contents[m["name"]] = dict(COUNTS)
                return {"snapshot": self.snapshots[m["name"]]}
            if method == "GET" and m:
                if m["name"] not in self.snapshots:
                    raise RuntimeError(f"snapshot_missing_exception [{REPO}:{m['name']}]")
                return {"snapshots": [self.snapshots[m["name"]]]}
            if method == "DELETE" and m:
                self.snapshots.pop(m["name"], None)
            return {}

        def fail(method, path, body):
            verifies = (method == "GET" and path.rstrip("/") == f"/_snapshot/{REPO}") or \
                (method == "POST" and path.rstrip("/") == f"/_snapshot/{REPO}/_verify")
            return verifies and not repository_registered

        self.es = FakeES(self.journal, route=route, fail=fail)
        self.docker = CaptureDocker(self, journal=self.journal, clock=self.clock, live_cluster=self.es,
                                    scratch_cluster=lambda c: ScratchCluster(self))
        self._deployed()
        _EDGES["monkeypatch"].setattr(subprocess, "run", self.docker)
        self.lab_module = load_script("lab_ops_1347_capture", LAB_OPS)
        self.ops = self.lab_module.LabOps(run=self.docker)
        self._observe_detection_rules()
        self._observe_fire()
        self.store = lock.DockerLockStore(run=self.docker)
        self.seam = DockerExecSeam(run=self.docker)
        self.freeze_dir = tmp_path / "held_out" / "freezes" / FREEZE_ID
        self.parts_dir = tmp_path / "parts"
        self.module = _module()  # loaded here, so a missing script is never the failure a raises() expects

    def _deployed(self) -> None:
        d = self.docker
        self.live_es = d.existing(CONTEXT, lock.LOCK_CONTAINER, "docker.elastic.co/elasticsearch/elasticsearch:9.3.3",
                                  cluster=self.es, env={"ELASTIC_PASSWORD": "live-elastic"})
        d.existing(CONTEXT, WATCHER, "alert-ticket-watcher")
        for host in HOSTS:
            mounts = []
            for mount in HOST_MOUNTS:
                name = f"{host}{mount.replace('/', '-')}"
                d.volume(CONTEXT, name).update(volume_files(host, mount))
                mounts.append((mount, "store", d.volumes[(CONTEXT, name)], False))
            c = d.existing(CONTEXT, host, f"soc-playground-{host}", mounts=mounts)
            c.extra.update(role_host=True, ps=ps_of(host))
        for stub, serves in STUBS.items():
            d.existing(CONTEXT, stub, f"soc-playground-{stub}").extra["serves"] = copy.deepcopy(serves)

    def _observe_detection_rules(self) -> None:
        real = self.ops.detection_rules

        def detection_rules(dest):
            self.journal.append(("detection_rules", str(dest)))
            self.held_at.setdefault("detection_rules", []).append(self.lock_held())
            self.watching_at.setdefault("detection_rules", []).append(self.watcher_running())
            self.at.setdefault("detection_rules", []).append(self.clock.last)
            names = real(dest)
            if self.fail_at == "detection_rules":
                raise RuntimeError("injected: detection_rules failed")
            return names

        self.ops.detection_rules = detection_rules

    def _observe_fire(self) -> None:
        real = self.ops.fire
        self.run_ids: list[str] = []

        def fire(scenario, lock_token):
            out = real(scenario, lock_token)
            run_id = out.get("run_id") if isinstance(out, dict) else None
            self.run_ids.append(run_id)
            _EDGES["run_ids"].append(run_id)
            return out

        self.ops.fire = fire

    # -- what a test reads ---------------------------------------------------------------------------

    def classify(self, argv: list[str]) -> str | None:
        """The capture step a docker call belongs to (None: not one, e.g. the live cluster's seam)."""
        if argv[:3] != ["docker", "--context", CONTEXT] or len(argv) < 4:
            return None
        verb, rest = argv[3], argv[4:]
        names = [a for a in rest if not a.startswith("-")]
        if verb == "exec":
            k = 0
            while k < len(rest) and rest[k].startswith("-"):
                k += 2 if rest[k] in ("-u", "--user", "-e", "--env", "-w", "--workdir") else 1
            name, command = (rest[k], rest[k + 1:]) if k < len(rest) else ("", [])
            if name == lock.LOCK_CONTAINER and LOCK_FILE in command:
                script = command[2] if len(command) > 2 else ""
                return "lock.create" if "set -C" in script else "lock.delete" if "rm " in script else "lock.read"
            if name in HOSTS:      # a batch command is one the committed catalog renders; any other host read
                return "fire" if any(scenario_of(a) for a in command) else "proc_tree"   # is the process tree
            if name in STUBS:
                return "stub_dumps"
            if name == VERIFY:
                return "verify.call"
            return None
        if verb in ("stop", "start", "restart", "kill") and WATCHER in names:
            return "hold_pickups" if verb in ("stop", "kill") else "release_pickups"
        if verb in ("commit", "save") or (verb == "image" and names[:1] == ["rm"]):
            return "commit_hosts"
        if verb == "inspect" and set(names) & set(HOSTS):
            return "copy_volumes"
        if verb == "run" and "--volumes-from" in rest:
            return "copy_volumes"
        if verb == "run" and VERIFY in rest:
            return "verify_restore"
        if verb == "rm" and VERIFY in rest:
            return "verify.call"
        return None

    def lock_record(self) -> str | None:
        data = self.docker.read_file(self.live_es, LOCK_FILE)
        return None if data is None else data.decode()

    def lock_held(self) -> bool:
        return self.lock_record() is not None

    def set_lock(self, record: str) -> None:
        store, key, _ro = self.docker.resolve(self.live_es, LOCK_FILE)
        self.docker.stores.setdefault(store, {})[key] = record.encode()

    def watcher_running(self) -> bool:
        return self.docker.containers[(CONTEXT, WATCHER)].state == "running"

    def lock_times(self) -> tuple:
        """(clock when capture's lock record was created, clock when it was deleted)."""
        taken = [c["clock"] for c in self.calls if c["step"] == "lock.create" and not c["held"] and c["held_after"]]
        freed = [c["clock"] for c in self.calls if c["step"] == "lock.delete" and c["held"] and not c["held_after"]]
        return (taken[0] if taken else None), (freed[-1] if freed else None)

    @property
    def fired(self) -> list[tuple[str, object, int, bool, bool]]:
        """Each firing of a scenario: (scenario, clock at its first command, how many commands it ran, the lock
        held at every one of them, the held lock record read since the previous firing and before this one's
        first command, as `chaos.lock.require` reads it to check the token), in order; a command of no listed
        scenario is a firing of None."""
        out: list[list] = []
        checked = False
        for c in self.calls:
            if c["step"] == "lock.read" and c["held"]:
                checked = True
            if c["step"] != "fire":
                continue
            sid = next((s for s in map(scenario_of, c["argv"]) if s), None)
            if out and out[-1][0] == sid:
                out[-1][2] += 1
                out[-1][3] = out[-1][3] and c["held"]
            else:
                out.append([sid, c["clock"], 1, c["held"], checked])
            checked = False
        return [tuple(f) for f in out]

    def stored(self) -> dict[str, bytes]:
        stored = self.parts_dir / FREEZE_ID
        return {p.name: p.read_bytes() for p in stored.rglob("*") if p.is_file()} if stored.exists() else {}

    def _seed(self, name: str) -> None:
        self.snapshots[name] = {"snapshot": name, "uuid": "AN-EARLIER-FREEZES-UUID", "state": "SUCCESS",
                                "indices": ["earlier-index"]}
        self.contents[name] = {"earlier-index": 5}
        self.preexisting[name] = copy.deepcopy(self.snapshots[name])

    def capture(self):
        return self.module.capture(
            self.freeze_dir, T=self.t, scenarios=self.scenarios, repository=REPO,
            tenant_settings=self.tenant_settings, ops=self.ops, es=self.seam, lock_store=self.store,
            parts_dir=self.parts_dir, clock=self.clock, captured_by="operator")

    def creates(self) -> list[tuple[str, str, object]]:
        return [r for r in self.es.requests
                if r[0] in ("PUT", "POST") and SNAP_URL.match(r[1].split("?", 1)[0])]

    def edges_modelled(self) -> None:
        """An unmodelled docker command is a gap in the fake, closed by a test repair, not a contract demand."""
        assert not self.docker.unmodelled, self.docker.unmodelled


# A capture step's failure as the real lab layer raises it: the attack runner exits (SystemExit) when a command
# of the batch fails, so `fire` failing raises that.
_FAILED = (Exception, SystemExit)


def _assert_the_parts_are_the_live_labs_at_T(rig, stored):
    """Every part holds what the real lab layer read from the live lab: each role host's process tree, image
    (committed paused) and two volumes, each stub's state in its seed shape, the committed rules; nothing else."""
    accounted = set()

    def one(name_pred, what):
        found = [n for n in stored if name_pred(n)]
        assert len(found) == 1, (what, found)
        accounted.add(found[0])
        return found[0]

    for host in HOSTS:
        one(lambda n, h=host: stored[n] == ps_of(h), f"the process tree of {host}")
        commits = [e for e in rig.docker.of_kind("commit") if e["container"].name == host]
        assert len(commits) == 1 and commits[0]["paused"], (host, commits)
        one(lambda n, img=commits[0]["image"]: stored[n] == img, f"the image of {host}")
        for mount in HOST_MOUNTS:
            want = volume_files(host, mount)

            def holds(n, want=want):
                try:
                    return tar_members(stored[n]) == want
                except tarfile.TarError:
                    return False
            one(holds, f"{host}:{mount}")
    stubs = tar_members(stored[STUBS_PART])
    accounted.add(STUBS_PART)
    assert yaml.safe_load(stubs["stub-change-mgmt.yaml"]) == STUBS["change-mgmt"]["/changes"]["changes"]
    assert json.loads(stubs["stub-ticket-server.json"]) == STUBS["ticket-server"]["/tickets"]["tickets"]
    assert json.loads(stubs["stub-threat-intel.json"]) == STUBS["threat-intel"]["/indicators"]["indicators"]
    assert json.loads(stubs["stub-cmdb-overlays.json"]) == {HOSTS[0]: STUBS["cmdb"][f"/admin/overlay/{HOSTS[0]}"]["overlay"]}
    assert tar_members(stored[RULES_PART]) == RULE_FILES
    accounted.add(RULES_PART)
    assert set(stored) == accounted, sorted(set(stored) - accounted)


STUBS_PART = "stubs.tar"


def test_a_capture_writes_one_freeze_of_every_part_with_the_verification_counts(tmp_path):
    """O1/A5: freeze.yaml names T, the snapshot (repository, name, UUID) with each index's count
    from the verification restore, every part (the rules at T included) by sha256, and who captured.
    The parts are what the real lab layer took from the live lab (C-rig)."""
    rig = Rig(tmp_path)
    rig.capture()

    doc = yaml.safe_load((rig.freeze_dir / "freeze.yaml").read_text())
    assert instant(doc["T"]) == T
    elastic = doc["elastic"]
    assert (elastic["repository"], elastic["uuid"], elastic["indices"]) == (REPO, SNAP_UUID, COUNTS)
    assert list(rig.snapshots) == [elastic["snapshot"]]
    stored = rig.stored()
    assert doc["parts"] == {n: sha(b) for n, b in stored.items()}  # bare lowercase hex (A8)
    _assert_the_parts_are_the_live_labs_at_T(rig, stored)
    assert doc["captured_by"] == "operator"
    assert rig.fired and rig.journal.ops().count("verify_restore") == 1
    assert rig.at["verify_restore"] and rig.restores == [(REPO, elastic["snapshot"])]
    assert (CONTEXT, VERIFY) not in rig.docker.containers, "the scratch cluster was left behind"
    rig.edges_modelled()


def test_the_snapshot_covers_the_configured_patterns_after_a_refresh(tmp_path):
    """O1/D24: one snapshot of every index the lab tenant's events and alerts patterns match, taken
    after a refresh of them (the parts come first, then refresh, then snapshot)."""
    rig = Rig(tmp_path)
    rig.capture()

    creates = rig.creates()
    assert len(creates) == 1, rig.es.requests
    indices = creates[0][2]["indices"]
    indices = indices.split(",") if isinstance(indices, str) else indices
    assert sorted(indices) == sorted(PATTERNS), creates
    j = rig.journal
    snapshot_at = next(i for i, (op, d) in enumerate(j) if op == "es" and SNAP_URL.match(d[1].split("?")[0])
                       and d[0] in ("PUT", "POST"))
    refreshes = [i for i, (op, d) in enumerate(j) if op == "es" and "_refresh" in d[1]]
    assert refreshes and max(refreshes) < snapshot_at
    assert j.last("copy_volumes") < min(refreshes)


def test_capture_only_verifies_the_registered_repository(tmp_path):
    """O1/A9: the operator registers the repository; capture checks it and never PUTs or
    POSTs to the repository itself, nor deletes it."""
    rig = Rig(tmp_path)
    rig.capture()

    repo_path = f"/_snapshot/{REPO}"
    verifies = [r for r in rig.es.requests
                if (r[0] == "GET" and r[1].split("?")[0].rstrip("/") == repo_path)
                or (r[0] == "POST" and r[1].split("?")[0].rstrip("/") == f"{repo_path}/_verify")]
    assert verifies, rig.es.requests
    assert not [r for r in rig.es.requests
                if r[0] in ("PUT", "POST", "DELETE") and r[1].split("?")[0].rstrip("/") == repo_path]


def test_an_unregistered_repository_fails_the_capture_without_registering_it(tmp_path):
    """O1/A9: the repository check fails: nothing registered, no snapshot, no freeze, lock free."""
    rig = Rig(tmp_path, repository_registered=False)
    with pytest.raises(_FAILED):
        rig.capture()

    assert not [r for r in rig.es.requests if r[0] in ("PUT", "POST")
                and r[1].split("?")[0].rstrip("/") in (f"/_snapshot/{REPO}",)]
    assert rig.snapshots == {} and not (rig.freeze_dir / "freeze.yaml").exists()
    assert not rig.lock_held()


def test_capture_holds_the_lock_and_the_pickups_off_from_the_batch_through_the_snapshot(tmp_path):
    """O1/O10 + held-out isolation: the capture lock is taken before anything fires and held
    through every part and the snapshot, then released before the verification restore; the
    watcher and live pickups are held off from the batch's start through the snapshot (the watcher is not
    running at any command of the batch, any part or the snapshot). Parts are taken at T, in the flow's
    order, then the snapshot."""
    rig = Rig(tmp_path)
    rig.capture()
    j = rig.journal

    assert j.first("lock.create") < j.first("hold_pickups") < j.first("fire")
    assert all(all(rig.held_at[s]) for s in ("fire", *PART_STEPS, "snapshot"))
    assert not any(any(rig.watching_at[s]) for s in ("fire", *PART_STEPS, "snapshot")), rig.watching_at
    assert rig.held_at["verify_restore"] == [False], "the lock was still held at the verification restore"
    snapshot_at = next(i for i, (op, d) in enumerate(j) if op == "es" and SNAP_URL.match(d[1].split("?")[0])
                       and d[0] in ("PUT", "POST"))
    assert j.first("release_pickups") > snapshot_at
    order = [(j.first(s), j.last(s)) for s in ("proc_tree", "stub_dumps", "commit_hosts", "copy_volumes")]
    assert all(a[1] < b[0] for a, b in zip(order, order[1:])) and order[-1][1] < snapshot_at, order
    assert j.first("proc_tree") > max(
        i for i, (op, at) in enumerate(j) if op == "clock.sleep_until" and at == T)
    assert all(at >= T for step in (*PART_STEPS, "snapshot") for at in rig.at[step]), rig.at
    assert not rig.lock_held() and rig.watcher_running()


def test_the_batch_is_spread_across_the_window_under_the_one_lock_token(tmp_path):
    """O1/O10: every scenario fires once (each of its commands, once) inside [T - max_age, T] and spread
    across it (not bunched), while the capture lock is held, and each firing first reads the held lock record:
    the attack runner checks that record against the token it is given (`chaos.lock.require`) and refuses to
    run otherwise, so a firing that read the held record and ran was given the lock's own token. A firing that
    skips the check (no lock store handed to the runner) fails here."""
    rig = Rig(tmp_path)
    rig.capture()

    fired = rig.fired
    assert sorted(s for s, *_ in fired) == sorted(SCENARIOS), fired
    assert all(n == commands_of(s) for s, _at, n, *_x in fired), fired
    times = [at for _s, at, *_x in fired]
    assert all(T - MAX_AGE <= at <= T for at in times), fired
    assert max(times) - min(times) >= MAX_AGE / 2, times
    assert all(held for *_x, held, _checked in fired), "a command of the batch ran while the capture lock was not held"
    assert all(checked for *_x, checked in fired), "a firing ran without reading the held lock record (no token check)"


def test_the_capture_lock_and_pickup_hold_last_the_whole_batch(tmp_path):
    """O10/A9: the lock is taken no later than the first firing and freed after T, so it is held
    for the whole >= 6 h batch; the pickups are held off over the same span."""
    rig = Rig(tmp_path)
    rig.capture()

    first_fire = min(at for _s, at, *_x in rig.fired)
    taken, freed = rig.lock_times()
    assert taken is not None and freed is not None, rig.calls
    assert taken <= first_fire and freed >= T and freed - taken >= MAX_AGE
    assert rig.at["hold_pickups"][0] <= first_fire and max(rig.at["release_pickups"]) >= T


@pytest.mark.parametrize("fail_at", [
    "hold_pickups", "fire", "proc_tree", "stub_dumps", "commit_hosts", "copy_volumes",
    "detection_rules", "snapshot", "verify_restore"])
def test_a_failed_capture_writes_nothing_and_frees_the_lock_and_the_pickups(tmp_path, fail_at):
    """O1/A9: all-or-nothing. Whatever step fails: no freeze.yaml, no parts left, no snapshot
    left in the repository, the lock free and the pickups resumed; the failure is raised."""
    rig = Rig(tmp_path, fail_at=fail_at)
    with pytest.raises(_FAILED):
        rig.capture()

    assert fail_at in rig.journal.ops() or fail_at == "snapshot", f"the {fail_at} step was never reached"
    assert not (rig.freeze_dir / "freeze.yaml").exists()
    stored = rig.parts_dir / FREEZE_ID
    assert not stored.exists() or not any(stored.rglob("*")), list(stored.rglob("*"))
    assert rig.snapshots == {}, "the capture left its own snapshot behind"
    assert not rig.lock_held()
    assert "release_pickups" in rig.journal.ops() and rig.watcher_running()
    assert (CONTEXT, VERIFY) not in rig.docker.containers


@pytest.mark.parametrize("state", ["PARTIAL", "FAILED"])
def test_a_snapshot_that_did_not_succeed_fails_the_capture_and_is_deleted(tmp_path, state):
    """O1/A9: a snapshot ending in any state but SUCCESS is a failed capture: nothing written,
    and the snapshot capture created is deleted."""
    rig = Rig(tmp_path, state=state)
    with pytest.raises(_FAILED):
        rig.capture()

    assert len(rig.creates()) == 1
    assert rig.snapshots == {} and not (rig.freeze_dir / "freeze.yaml").exists()
    assert not rig.lock_held() and "verify_restore" not in rig.journal.ops()


def test_a_capture_is_refused_while_a_fault_is_active_or_the_lock_is_held(tmp_path):
    """O1 (no fault is active: a chaos ledger record still on the stack) and O10: nothing fires and nothing is
    written. Control: the same rig with neither captures (the first test)."""
    faulted = Rig(tmp_path / "a", faults=["data-drop-syslog"])
    with pytest.raises(_FAILED, match="data-drop-syslog"):
        faulted.capture()
    held = Rig(tmp_path / "b")
    held.set_lock("someone-else")
    with pytest.raises(_FAILED):
        held.capture()

    for rig in (faulted, held):
        assert "fire" not in rig.journal.ops() and not rig.es.requests
        assert not (rig.freeze_dir / "freeze.yaml").exists() and rig.snapshots == {}
        assert not rig.docker.of_kind("host-command")
    assert held.lock_record() == "someone-else"
    assert not faulted.lock_held()


_NOT_A_REFUSAL = (AttributeError, TypeError, NameError, ImportError)


@pytest.mark.parametrize("patterns", [PATTERNS, ["logs-system.*", ".alerts-lab-*"]])
def test_the_freeze_records_the_patterns_the_lab_tenant_configures_and_capture_takes_none(tmp_path, patterns):
    """D24/O1: freeze.yaml's `patterns` are the tenant's events and alerts patterns as its config.env
    has them, and the snapshot is of exactly those; capture has no `patterns` parameter."""
    rig = Rig(tmp_path, patterns=patterns)
    settings = (rig.tenant_settings / "systems" / "elastic" / "config.env").read_text()
    rig.capture()

    doc = yaml.safe_load((rig.freeze_dir / "freeze.yaml").read_text())
    assert doc["patterns"] == patterns
    body = rig.creates()[0][2]["indices"]
    assert sorted(body.split(",") if isinstance(body, str) else body) == sorted(patterns)
    assert "patterns" not in inspect.signature(rig.module.capture).parameters
    assert (rig.tenant_settings / "systems" / "elastic" / "config.env").read_text() == settings


# -- C7: the moments are ordered (O1 "wait until T", A9 max_age, O7) --------------------------------

_NOW = T - MAX_AGE - timedelta(minutes=5)
_ONE = timedelta(seconds=1)


@pytest.mark.parametrize("scenarios, t, accepted", [
    ([], _NOW, True), ([], _NOW - _ONE, False), ([], _NOW + timedelta(hours=1), True),
    (SCENARIOS, _NOW + MAX_AGE, True), (SCENARIOS, _NOW + MAX_AGE - _ONE, False),
    (SCENARIOS, _NOW + MAX_AGE + _ONE, True)], ids=[
    "no-scenarios-T-is-now", "no-scenarios-T-one-second-past", "no-scenarios-T-ahead",
    "scenarios-T-exactly-max-age-ahead", "scenarios-T-one-second-short", "scenarios-T-further-ahead"])
def test_T_is_not_before_the_capture_starts_and_a_batch_has_the_max_age_before_T(tmp_path, scenarios, t, accepted):
    """O1/A9: with the clock standing at `now`, T >= now captures (and with scenarios T - now >= max_age);
    one second less is refused with nothing fired, nothing written, nothing snapshotted and the lock free."""
    rig = Rig(tmp_path, t=t, scenarios=scenarios, clock_start=_NOW, clock_step=0)
    if accepted:
        rig.capture()
        assert instant(yaml.safe_load((rig.freeze_dir / "freeze.yaml").read_text())["T"]) == t
        assert sorted(s for s, *_ in rig.fired) == sorted(scenarios)
        return
    with pytest.raises(_FAILED) as caught:
        rig.capture()

    assert not isinstance(caught.value, _NOT_A_REFUSAL), repr(caught.value)
    assert not rig.fired and not rig.docker.of_kind("host-command") and not (rig.freeze_dir / "freeze.yaml").exists()
    stored = rig.parts_dir / FREEZE_ID
    assert not stored.exists() or not any(stored.rglob("*"))
    assert rig.snapshots == {} and not rig.lock_held()
    assert rig.journal.ops().count("hold_pickups") == rig.journal.ops().count("release_pickups")
    assert rig.watcher_running()


# -- B3: capture removes only what it wrote ----------------------------------------------------------

_BEFORE_THE_SNAPSHOT = ["hold_pickups", "fire", "proc_tree", "stub_dumps", "commit_hosts", "copy_volumes",
                        "detection_rules"]


@pytest.mark.parametrize("occupied, fail_at, state", [
    *[("freeze-id", s, "SUCCESS") for s in [*_BEFORE_THE_SNAPSHOT, "snapshot", "verify_restore"]],
    ("freeze-id", None, "PARTIAL"),
    ("asked-name", "snapshot", "SUCCESS"), ("asked-name", None, "PARTIAL"),
    *[("other-name", s, "SUCCESS") for s in [*_BEFORE_THE_SNAPSHOT, "snapshot", "verify_restore"]],
    ("other-name", None, "PARTIAL")])
def test_a_failed_capture_leaves_the_repositorys_snapshots_exactly_as_it_found_them(tmp_path, occupied, fail_at, state):
    """O1/A9: whatever step fails, a snapshot that was in the repository before capture started (under the
    freeze's id, under the name capture asks for, or another) is still there, unchanged; capture deletes
    only what it created."""
    rig = Rig(tmp_path, fail_at=fail_at, state=state, occupied=occupied)
    with pytest.raises(_FAILED) as caught:
        rig.capture()

    assert not isinstance(caught.value, _NOT_A_REFUSAL), repr(caught.value)
    assert rig.preexisting, "the repository held nothing: the fixture did not reach the snapshot step"
    assert rig.snapshots == rig.preexisting
    assert not (rig.freeze_dir / "freeze.yaml").exists() and not rig.lock_held()


@pytest.mark.parametrize("occupied", ["freeze-id", "asked-name"])
def test_a_capture_whose_snapshot_name_is_taken_fails_or_takes_a_fresh_name_and_leaves_the_old_snapshot_alone(tmp_path, occupied):
    """O1/A9: the design fixes only that a pre-existing same-name snapshot is left exactly as it was. Capture
    may fail (nothing written, nothing left) or snapshot under a fresh name (a whole freeze that names it)."""
    rig = Rig(tmp_path, occupied=occupied)
    try:
        rig.capture()
        failed = None
    except _FAILED as exc:  # noqa: BLE001 - either outcome is allowed; the old snapshot is what is checked
        failed = exc

    assert not isinstance(failed, _NOT_A_REFUSAL), repr(failed)
    assert rig.preexisting, "the repository held nothing: the fixture did not reach the snapshot step"
    assert all(rig.snapshots.get(name) == old for name, old in rig.preexisting.items()), "the old snapshot changed"
    assert not rig.lock_held()
    if failed is not None:
        assert rig.snapshots == rig.preexisting and not (rig.freeze_dir / "freeze.yaml").exists()
        return
    elastic = yaml.safe_load((rig.freeze_dir / "freeze.yaml").read_text())["elastic"]
    assert elastic["snapshot"] not in rig.preexisting and elastic["uuid"] == SNAP_UUID
    assert set(rig.snapshots) == set(rig.preexisting) | {elastic["snapshot"]}
    assert rig.restores == [(REPO, elastic["snapshot"])]


def test_fire_writes_the_attack_runs_into_the_configured_runs_dir_not_the_repository(tmp_path):
    """r6.4.3 review repair: the batch's run records go where `V2_ATTACK_RUNS_DIR` says (one per firing, named by
    the run id `fire` returned); none lands in the repository's `attacks/runs/`."""
    rig = Rig(tmp_path)
    rig.capture()

    assert len(rig.run_ids) == len(SCENARIOS) and all(rig.run_ids), rig.run_ids
    configured = _EDGES["attack_runs"]
    assert sorted(p.name for p in configured.iterdir()) == sorted(rig.run_ids), list(configured.iterdir())
    assert not [r for r in rig.run_ids if (REPO_RUNS / r).exists()], "a run record was written into the repository"


def _point_defaults(monkeypatch, fn, fake) -> None:
    """Replace a `run=subprocess.run` default (bound when its module was imported) by the rig docker."""
    real = _EDGES["real_run"]
    if fn.__defaults__:
        monkeypatch.setattr(fn, "__defaults__", tuple(fake if d is real else d for d in fn.__defaults__))
    if fn.__kwdefaults__:
        monkeypatch.setattr(fn, "__kwdefaults__", {k: fake if d is real else d for k, d in fn.__kwdefaults__.items()})


def _aware(value) -> datetime:
    """A recorded instant that must carry its zone: a naive one fails here instead of being read as UTC."""
    dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    assert dt.tzinfo is not None, f"a naive instant was recorded: {value!r}"
    return dt


def test_capture_main_freezes_a_T_given_without_an_offset_as_that_UTC_instant_whatever_the_local_zone(tmp_path, monkeypatch):
    """r6.4.3 finding 7/O1, end to end: `capture_case.py <freeze> --T <naive>` with local time two hours ahead
    (TZ=Etc/GMT-2) runs the real capture over the rig and freezes exactly that instant read as UTC. Read as local
    time, T would be two hours in the past and refused; kept naive, the real capture cannot compare it."""
    rig = Rig(tmp_path, scenarios=[])
    rig.module.main  # noqa: B018 - the script is loaded (and its directory importable) before lab_ops is imported
    import lab_ops

    for cls in (lab_ops.LabOps, DockerExecSeam, lock.DockerLockStore):
        _point_defaults(monkeypatch, cls.__init__, rig.docker)
    monkeypatch.setenv("V2_FROZEN_TENANT_DIR", str(tmp_path / "tenant"))
    moment = (datetime.now(timezone.utc) + timedelta(seconds=3)).replace(microsecond=0)
    saved = os.environ.get("TZ")
    os.environ["TZ"] = "Etc/GMT-2"
    time.tzset()
    try:
        rc = rig.module.main([str(rig.freeze_dir), "--repository", REPO, "--T", moment.strftime("%Y-%m-%dT%H:%M:%S"),
                              "--parts-dir", str(rig.parts_dir), "--captured-by", "operator"])
    finally:
        if saved is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = saved
        time.tzset()

    assert rc == 0, rc
    doc = yaml.safe_load((rig.freeze_dir / "freeze.yaml").read_text())
    assert _aware(doc["T"]) == moment, (doc["T"], moment)
    rig.edges_modelled()


# -- r6.4.3 finding 7 (C-parse): an operator-given instant without an offset is UTC -------------------------


@pytest.mark.parametrize("given, meant", [("2026-11-10T14:00:00", "2026-11-10T14:00:00Z"),
                                          ("2026-11-10T14:00:00Z", "2026-11-10T14:00:00Z"),
                                          ("2026-11-10T16:00:00+02:00", "2026-11-10T14:00:00Z")])
def test_capture_reads_a_T_given_without_an_offset_as_UTC_whatever_the_local_zone(tmp_path, monkeypatch, given, meant):
    """r6.4.3 finding 7/O1: `capture_case.py --T 2026-11-10T14:00:00` means 14:00Z, as its help says, even
    where local time is two hours ahead (TZ=Etc/GMT-2); a value with an offset keeps it."""
    import time

    module = _module()
    seen = {}

    def capture(freeze_dir, **kw):
        seen.update(kw)
        return {}

    monkeypatch.setattr(module, "capture", capture)
    monkeypatch.setenv("TZ", "Etc/GMT-2")
    time.tzset()
    try:
        monkeypatch.setenv("V2_FROZEN_TENANT_DIR", str(tmp_path / "tenant"))
        (tmp_path / "tenant" / "settings" / "systems" / "elastic").mkdir(parents=True)
        (tmp_path / "tenant" / "settings" / "systems" / "elastic" / "config.env").write_text(config_env(*PATTERNS))
        module.main([str(tmp_path / "freezes" / FREEZE_ID), "--repository", REPO, "--T", given,
                     "--parts-dir", str(tmp_path / "parts")])
    finally:
        monkeypatch.undo()
        time.tzset()

    assert "T" in seen, "capture was not called"
    assert _aware(seen["T"]) == instant(meant), seen["T"]
