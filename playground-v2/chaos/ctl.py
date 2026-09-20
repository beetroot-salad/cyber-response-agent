#!/usr/bin/env python3
"""M1 — the chaos control plane: `list`, `plan`, `activate`, `revert`, `status`, `audit`.

Every mutation travels over `docker --context soc-playground exec`
(`DockerExecSeam`) — CMDB via a `python3 -c <urllib>` round trip, Elasticsearch
via `curl` inside the `elasticsearch` container. No path from outside the
containers, and no long-lived controller process — the two properties that
keep the controller itself out of the telemetry the agent-under-test reads
(O7).

A fault is a change to named resources — a host's CMDB overlay, an ingest
pipeline — and the controller records what each one held *before* it
touched it:

    plan     resolve profile + seed against the container's baked inventory,
             run the O4 guard on the resolved mutations; no write to anything
    apply    refuse if an active record already owns a resource; snapshot
             each resource's before-state; write a pending ledger record;
             push each change and mark it applied in the record; then stamp
             the record active
    revert   restore each applied resource's before-state, in reverse
    status   compare every owned resource's live state to its recorded
             after-state, and the baked inventory to live for anything
             nobody owns

`activate` is plan + apply in one call. `attacks/runner.py --chaos` calls
them separately so a bad profile fails before the synthetic CR is posted.

`activate`/`revert`/`status` all take an injectable `execer=` so tests never
need the live stack — see chaos/tests/_fakes.py:FakeExecSeam. The functions
also take explicit `profiles_dir=`/`rules_dir=`/`ledger_dir=` for the same
reason; omitted, they default to this package's own committed locations.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shlex
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

HERE = Path(__file__).resolve().parent
# Runnable both as `import chaos.ctl` (a package import already puts
# playground-v2/ on sys.path — see chaos/tests/conftest.py) and as a direct
# script (`./ctl.py ...`, matching attacks/runner.py's usage shape), where
# sys.path[0] is this directory, not its parent. Absolute imports below need
# playground-v2/ on the path either way; the insert is a no-op when it's
# already there.
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

from chaos import ledger as ledger_mod  # noqa: E402
from chaos.audit import audit_payloads  # noqa: E402
from chaos.guard import check_mutations, check_profile  # noqa: E402
from chaos.mutations import TOMBSTONE, resolve_mutations  # noqa: E402
from chaos.profiles import list_profiles, load_profile  # noqa: E402
from chaos.seam import SeamError, SeamNotFound  # noqa: E402

DEFAULT_PROFILES_DIR = HERE / "profiles"
DEFAULT_RULES_DIR = HERE.parent / "detection-rules"
DEFAULT_LEDGER_DIR = HERE / "ledger"

DOCKER_CONTEXT = "soc-playground"
BAKED_INVENTORY_PATH = "/opt/cmdb/inventory.yaml"

CMDB_OVERLAY = "cmdb-overlay"
ES_PIPELINE = "es-pipeline"
TOMBSTONE_KEY = next(iter(TOMBSTONE))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_ref() -> str:
    return f"chaos-{uuid.uuid4().hex[:12]}"


def _fingerprint(resources: list[dict[str, Any]]) -> str:
    blob = json.dumps([(r["kind"], r["name"], r["after"]) for r in resources], sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


class DockerExecSeam:
    """The real exec seam. Nothing else in this module talks to the stack.

    Every call shells `docker --context soc-playground exec` into the target
    container itself; there is no host-side network path to the stub or to
    Elasticsearch (O7 — a direct host-side HTTP call would show up as a
    gateway-IP flow in the agent's own Zeek telemetry, which is exactly what
    keeps the controller invisible to the agent-under-test). `run=` is an
    injection seam over `subprocess.run` so a test can assert on the argv
    without actually shelling out — see chaos/tests/test_m1_real_seam.py.

    Contract (chaos/seam.py): each call returns the backend's payload or
    raises SeamError / SeamNotFound. The in-container command prints the
    response body followed by the HTTP status on its own last line; a
    non-zero exit is a transport failure.
    """

    def __init__(self, run: Any = subprocess.run) -> None:
        self._run = run

    def cmdb_request(self, method: str, path: str, body: Any = None) -> Any:
        script = (
            "import json, sys, urllib.request, urllib.error\n"
            f"req = urllib.request.Request('http://127.0.0.1:8080{path}', method={method.upper()!r})\n"
            "raw = sys.stdin.read()\n"
            "if raw:\n"
            "    req.data = raw.encode()\n"
            "    req.add_header('Content-Type', 'application/json')\n"
            "try:\n"
            "    with urllib.request.urlopen(req, timeout=10) as resp:\n"
            "        sys.stdout.write(resp.read().decode() + '\\n' + str(resp.status))\n"
            "except urllib.error.HTTPError as e:\n"
            "    sys.stdout.write(e.read().decode() + '\\n' + str(e.code))\n"
        )
        payload = json.dumps(body) if body is not None else ""
        args = [
            "docker", "--context", DOCKER_CONTEXT, "exec", "-i",
            "cmdb", "python3", "-c", script,
        ]
        proc = self._run(args, input=payload, capture_output=True, text=True)
        return self._parse(proc, f"cmdb {method.upper()} {path}")

    def es_request(self, method: str, path: str, body: Any = None) -> Any:
        parts = ["curl", "-s", "-k", "-u", "elastic:$ELASTIC_PASSWORD", "-X", method.upper(),
                 "-w", "\n%{http_code}", f"https://localhost:9200{path}"]
        if body is not None:
            parts += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
        quoted = " ".join(
            '"elastic:$ELASTIC_PASSWORD"' if part == "elastic:$ELASTIC_PASSWORD" else shlex.quote(part)
            for part in parts
        )
        args = ["docker", "--context", DOCKER_CONTEXT, "exec", "elasticsearch", "bash", "-lc", quoted]
        proc = self._run(args, capture_output=True, text=True)
        return self._parse(proc, f"elasticsearch {method.upper()} {path}")

    def read_container_file(self, container: str, path: str) -> str:
        args = ["docker", "--context", DOCKER_CONTEXT, "exec", container, "cat", path]
        proc = self._run(args, capture_output=True, text=True)
        if proc.returncode != 0:
            raise SeamError(f"{container}:{path}: rc={proc.returncode} {proc.stderr.strip()}")
        return proc.stdout

    @staticmethod
    def _parse(proc: "subprocess.CompletedProcess[str]", what: str) -> Any:
        if proc.returncode != 0:
            raise SeamError(f"{what}: transport failed rc={proc.returncode}: {proc.stderr.strip()}")
        text, _, status_text = proc.stdout.rstrip().rpartition("\n")
        try:
            status = int(status_text.strip())
        except ValueError:
            raise SeamError(f"{what}: no HTTP status in response: {proc.stdout[-200:]!r}") from None
        text = text.strip()
        payload: Any
        if not text:
            payload = {}
        else:
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = {"raw": text}
        if status == 404:
            raise SeamNotFound(f"{what}: 404", status=status, payload=payload)
        if not 200 <= status < 300:
            raise SeamError(f"{what}: HTTP {status}: {payload}", status=status, payload=payload)
        return payload


class ChaosApplyError(RuntimeError):
    """A mutation did not reach the stack — nothing about it may be recorded
    as ground truth (O5): a failed injection is not an injection."""


class OverlapRefused(RuntimeError):
    """An active ledger record already owns a resource this profile would
    touch. Two faults on one resource cannot be reverted independently, so
    the second is refused rather than stacked."""


# -- resources ----------------------------------------------------------------
#
# A resource is {kind, name, before, after, patches, applied}. `before` is
# what the stack held when apply started (None = absent), `after` is what it
# holds once every patch has landed, `patches` are the calls that get it
# there, `applied` flips as each resource lands and is what revert/status
# read.


def _snapshot(kind: str, name: str, execer: Any) -> Optional[dict[str, Any]]:
    if kind == CMDB_OVERLAY:
        payload = execer.cmdb_request("GET", f"/admin/overlay/{name}")
        overlay = payload.get("overlay") if isinstance(payload, dict) else None
        return dict(overlay) if overlay else None
    try:
        payload = execer.es_request("GET", f"/_ingest/pipeline/{name}")
    except SeamNotFound:
        return None
    body = payload.get(name) if isinstance(payload, dict) else None
    return copy.deepcopy(body) if body else None


def _resources_for(mode: str, mutations: list[dict[str, Any]], execer: Any) -> list[dict[str, Any]]:
    """Group the mutations by the resource they touch and snapshot each one."""
    resources: dict[tuple[str, str], dict[str, Any]] = {}

    def resource(kind: str, name: str) -> dict[str, Any]:
        key = (kind, name)
        if key not in resources:
            before = _snapshot(kind, name, execer)
            resources[key] = {
                "kind": kind,
                "name": name,
                "before": before,
                "after": copy.deepcopy(before) if before is not None else {},
                "patches": [],
                "applied": False,
            }
        return resources[key]

    for m in mutations:
        if mode == "cmdb-stale":
            patch = {m["field"]: m["new_value"]} if m["kind"] == "field-flip" else dict(m["new_value"])
            res = resource(CMDB_OVERLAY, m["host"])
            res["after"].update(patch)  # the stub's POST is a shallow merge
            res["patches"].append(patch)
        else:
            res = resource(ES_PIPELINE, m["pipeline"])
            res["after"].setdefault("processors", []).append(m["processor"])
            res["patches"].append(m["processor"])
    return list(resources.values())


def _push(res: dict[str, Any], execer: Any) -> None:
    if res["kind"] == CMDB_OVERLAY:
        for patch in res["patches"]:
            execer.cmdb_request("POST", f"/admin/overlay/{res['name']}", patch)
    else:
        execer.es_request("PUT", f"/_ingest/pipeline/{res['name']}", res["after"])


def _restore(res: dict[str, Any], execer: Any) -> None:
    """Put the resource back to exactly its before-state."""
    if res["kind"] == CMDB_OVERLAY:
        path = f"/admin/overlay/{res['name']}"
        if res["before"] is None:
            execer.cmdb_request("DELETE", path)
        else:
            execer.cmdb_request("PUT", path, res["before"])
    else:
        path = f"/_ingest/pipeline/{res['name']}"
        if res["before"] is None:
            try:
                execer.es_request("DELETE", path)
            except SeamNotFound:
                pass  # already absent — the state we wanted
        else:
            execer.es_request("PUT", path, res["before"])


def _owned_resources(records: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    owned: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        if record.get("reverted_at"):
            continue
        for res in record.get("resources") or []:
            owned[(res["kind"], res["name"])] = record
    return owned


# -- plan / apply / activate ----------------------------------------------------


def _baked_inventory(execer: Any) -> dict[str, Any]:
    # The container's own copy, never the working-tree file: the two disagree
    # exactly when the image is stale, and the stack serves the baked one.
    return yaml.safe_load(execer.read_container_file("cmdb", BAKED_INVENTORY_PATH)) or {}


def plan(
    profile_id: str,
    *,
    seed: Optional[int] = None,
    execer: Any = None,
    profiles_dir: Optional[Path] = None,
    rules_dir: Optional[Path] = None,
) -> dict[str, Any]:
    """Resolve a profile into the mutations `apply` would push. Reads only."""
    execer = execer if execer is not None else DockerExecSeam()
    profiles_dir = Path(profiles_dir) if profiles_dir is not None else DEFAULT_PROFILES_DIR
    rules_dir = Path(rules_dir) if rules_dir is not None else DEFAULT_RULES_DIR

    profile = load_profile(profile_id, profiles_dir=profiles_dir)
    # The guard is a precondition, not a report: nothing below this line runs
    # until it clears, so a refused profile mutates nothing (O4). Checked on
    # the parameters first (no stack read needed to refuse) and again on the
    # resolved mutations, which is the check that actually gates the push.
    check_profile(profile, rules_dir=rules_dir)
    effective_seed = seed if seed is not None else profile.seed
    mutations = resolve_mutations(profile, seed=effective_seed, inventory=_baked_inventory(execer))
    check_mutations(mutations, rules_dir=rules_dir)
    return {
        "profile_id": profile.id,
        "seed": effective_seed,
        "mode": profile.mode,
        "resolved_mutations": mutations,
    }


def apply(
    planned: dict[str, Any],
    *,
    execer: Any = None,
    ledger_dir: Optional[Path] = None,
) -> dict[str, Any]:
    """Push a plan to the stack, recording every step in the ledger first."""
    execer = execer if execer is not None else DockerExecSeam()
    ledger_dir = Path(ledger_dir) if ledger_dir is not None else DEFAULT_LEDGER_DIR

    mode = planned["mode"]
    mutations = planned["resolved_mutations"]
    owned = _owned_resources(ledger_mod.read_records(ledger_dir))
    wanted = {
        (CMDB_OVERLAY, m["host"]) if mode == "cmdb-stale" else (ES_PIPELINE, m["pipeline"])
        for m in mutations
    }
    clashes = sorted(wanted & set(owned))
    if clashes:
        owners = {f"{k}:{n}": owned[(k, n)]["ledger_ref"] for k, n in clashes}
        raise OverlapRefused(f"{planned['profile_id']}: resources already owned by an active record: {owners}")

    resources = _resources_for(mode, mutations, execer)
    record = {
        "ledger_ref": _new_ref(),
        "profile_id": planned["profile_id"],
        "seed": planned["seed"],
        "mode": mode,
        "resolved_mutations": mutations,
        "resources": resources,
        "status": "pending",
        "activated_at": None,
        "live_fingerprint": _fingerprint(resources),
    }
    # Intent goes to disk before the first mutation reaches the stack: from
    # here on there is never a live fault with no record pointing at it.
    ledger_mod.write_record(ledger_dir, record)

    for res in resources:
        try:
            _push(res, execer)
        except SeamError as exc:
            raise _roll_back(record, ledger_dir, execer, exc) from exc
        res["applied"] = True
        ledger_mod.write_record(ledger_dir, record)

    record["status"] = "active"
    record["activated_at"] = _now_iso()
    ledger_mod.write_record(ledger_dir, record)
    return record


def _roll_back(record: dict[str, Any], ledger_dir: Path, execer: Any, cause: SeamError) -> ChaosApplyError:
    """A partial apply is rolled back and its record removed (a failed
    injection is not an injection). If the rollback itself fails, the record
    stays, marked failed, so `revert --all` / `status` still see the fault.
    Returns the error for the caller to raise."""
    failures: list[str] = []
    for res in reversed(record["resources"]):
        if not res["applied"]:
            continue
        try:
            _restore(res, execer)
            res["applied"] = False
            ledger_mod.write_record(ledger_dir, record)
        except SeamError as exc:
            failures.append(f"{res['kind']}:{res['name']}: {exc}")
    if failures:
        record["status"] = "failed"
        ledger_mod.write_record(ledger_dir, record)
        return ChaosApplyError(
            f"{record['profile_id']}: apply failed ({cause}) and rollback left resources live "
            f"({'; '.join(failures)}); ledger {record['ledger_ref']} keeps them — revert it"
        )
    ledger_mod.delete_record(ledger_dir, record["ledger_ref"])
    return ChaosApplyError(f"{record['profile_id']}: apply failed, rolled back: {cause}")


def activate(
    profile_id: str,
    *,
    seed: Optional[int] = None,
    execer: Any = None,
    profiles_dir: Optional[Path] = None,
    rules_dir: Optional[Path] = None,
    ledger_dir: Optional[Path] = None,
) -> dict[str, Any]:
    execer = execer if execer is not None else DockerExecSeam()
    planned = plan(profile_id, seed=seed, execer=execer, profiles_dir=profiles_dir, rules_dir=rules_dir)
    return apply(planned, execer=execer, ledger_dir=ledger_dir)


# -- revert ---------------------------------------------------------------------


def revert(
    ledger_ref: str,
    *,
    execer: Any = None,
    profiles_dir: Optional[Path] = None,  # accepted, unused: revert replays the ledger's own record
    ledger_dir: Optional[Path] = None,
) -> dict[str, Any]:
    execer = execer if execer is not None else DockerExecSeam()
    ledger_dir = Path(ledger_dir) if ledger_dir is not None else DEFAULT_LEDGER_DIR

    record = ledger_mod.find_record(ledger_dir, ledger_ref)
    if record is None:
        raise KeyError(f"no ledger record for {ledger_ref!r} in {ledger_dir}")
    if record.get("reverted_at"):
        return record  # already reverted — idempotent, not a second undo

    # Every applied resource is attempted, in reverse, before raising, so one
    # failed restore doesn't strand the others live; each success is written
    # down as it happens, so a retry only redoes what is still applied.
    failures: list[str] = []
    for res in reversed(record["resources"]):
        if not res["applied"]:
            continue
        try:
            _restore(res, execer)
            res["applied"] = False
            ledger_mod.write_record(ledger_dir, record)
        except SeamError as exc:
            failures.append(f"{res['kind']}:{res['name']}: {exc}")
    if failures:
        record["status"] = "revert-failed"
        ledger_mod.write_record(ledger_dir, record)
        raise ChaosApplyError(f"revert {ledger_ref}: {'; '.join(failures)}")

    record["status"] = "reverted"
    record["reverted_at"] = _now_iso()
    ledger_mod.write_record(ledger_dir, record)
    return record


def revert_all(
    *,
    execer: Any = None,
    ledger_dir: Optional[Path] = None,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Revert every active record, attempting each one even after a failure.

    Returns (reverted records, {ledger_ref: error} for the ones that did not
    fully revert). One failed restore must not leave the others live and
    unattempted.
    """
    execer = execer if execer is not None else DockerExecSeam()
    ledger_dir = Path(ledger_dir) if ledger_dir is not None else DEFAULT_LEDGER_DIR
    reverted: list[dict[str, Any]] = []
    failed: dict[str, str] = {}
    for record in ledger_mod.read_records(ledger_dir):
        if record.get("reverted_at"):
            continue
        try:
            reverted.append(revert(record["ledger_ref"], execer=execer, ledger_dir=ledger_dir))
        except (ChaosApplyError, SeamError) as exc:
            failed[record["ledger_ref"]] = str(exc)
    return reverted, failed


# -- status ---------------------------------------------------------------------


def status(
    *,
    execer: Any = None,
    profiles_dir: Optional[Path] = None,  # accepted for symmetry with activate/revert; unused
    ledger_dir: Optional[Path] = None,
) -> dict[str, Any]:
    """Reconcile the ledger against live state (O1).

    Persistence is asymmetric — the CMDB overlay is in-memory (a container
    restart silently reverts it) and an ingest-pipeline processor lives in
    cluster state (it silently survives a revert that only touched the
    ledger) — so this never trusts the ledger alone. A backend that cannot
    be read raises (SeamError) rather than being reported as drift.
    """
    execer = execer if execer is not None else DockerExecSeam()
    ledger_dir = Path(ledger_dir) if ledger_dir is not None else DEFAULT_LEDGER_DIR

    records = ledger_mod.read_records(ledger_dir)
    active_records = [r for r in records if not r.get("reverted_at")]

    baked_hosts = {h["name"]: h for h in _baked_inventory(execer).get("hosts") or []}
    hosts_payload = execer.cmdb_request("GET", "/hosts")
    live_hosts = {h["name"]: h for h in (hosts_payload.get("hosts") or [])}
    try:
        live_pipelines = execer.es_request("GET", "/_ingest/pipeline/*@custom")
    except SeamNotFound:
        live_pipelines = {}

    drift: list[dict[str, Any]] = []

    # The reconciled expectation: baked inventory with every applied
    # overlay laid on top, and every applied pipeline's after-state. Diffing
    # *this* against live — rather than only each record's own claim — is
    # what catches drift the ledger never predicted: a stray overlay nobody's
    # record explains is exactly the asymmetric-persistence case, and a
    # ledger-only check can't see it when the ledger itself is what went
    # stale (lost on a restart, or empty because the edit was made by hand).
    expected_hosts: dict[str, dict[str, Any]] = {name: dict(rec) for name, rec in baked_hosts.items()}
    owner_of: dict[tuple[str, str], dict[str, Any]] = {}  # (host, field | "*") -> record
    expected_pipelines: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}  # name -> (after, record)

    for record in active_records:
        if record.get("status") != "active":
            drift.append(
                {
                    "type": "incomplete-record",
                    "ledger_ref": record["ledger_ref"],
                    "profile_id": record["profile_id"],
                    "status": record.get("status"),
                    "applied": [f"{r['kind']}:{r['name']}" for r in record["resources"] if r["applied"]],
                }
            )
        for m in record["resolved_mutations"]:
            # The image itself can move independent of the overlay (a
            # rebuild) — catch the ledger's premise going stale.
            if m.get("kind") == "field-flip":
                baked_value = baked_hosts.get(m["host"], {}).get(m["field"])
                if baked_value != m["old_value"]:
                    drift.append(
                        {
                            "type": "baked-inventory-moved",
                            "profile_id": record["profile_id"],
                            "host": m["host"],
                            "field": m["field"],
                            "ledger_old_value": m["old_value"],
                            "baked_value": baked_value,
                        }
                    )
        for res in record["resources"]:
            if not res["applied"]:
                continue
            if res["kind"] == ES_PIPELINE:
                expected_pipelines[res["name"]] = (res["after"], record)
                continue
            host, after = res["name"], res["after"]
            if after.get(TOMBSTONE_KEY):
                expected_hosts.pop(host, None)
                owner_of[(host, "*")] = record
                continue
            if host not in baked_hosts:
                owner_of[(host, "*")] = record
            expected_hosts[host] = {**baked_hosts.get(host, {"name": host}), **after}
            for field in after:
                owner_of[(host, field)] = record

    for name in sorted(set(expected_hosts) | set(live_hosts)):
        expected = expected_hosts.get(name)
        live = live_hosts.get(name)
        owner = owner_of.get((name, "*"))
        if expected is None and live is not None:
            drift.append(
                {
                    "type": "unexpected-live-host",
                    "host": name,
                    "profile_id": owner["profile_id"] if owner else None,
                }
            )
        elif expected is not None and live is None:
            drift.append(
                {
                    "type": "cmdb-host-missing",
                    "host": name,
                    "profile_id": owner["profile_id"] if owner else None,
                }
            )
        elif expected is not None and live is not None:
            for field in sorted(set(expected) | set(live)):
                if expected.get(field) == live.get(field):
                    continue
                field_owner = owner_of.get((name, field)) or owner
                drift.append(
                    {
                        "type": "cmdb-field-mismatch",
                        "host": name,
                        "field": field,
                        "expected": expected.get(field),
                        "live": live.get(field),
                        "profile_id": field_owner["profile_id"] if field_owner else None,
                    }
                )

    for name in sorted(set(live_pipelines) - set(expected_pipelines)):
        drift.append({"type": "stray-pipeline", "pipeline": name})
    for name in sorted(expected_pipelines):
        after, record = expected_pipelines[name]
        live = live_pipelines.get(name)
        if live is None:
            drift.append({"type": "pipeline-missing", "pipeline": name, "profile_id": record["profile_id"]})
        elif live.get("processors") != after.get("processors"):
            drift.append(
                {
                    "type": "pipeline-mismatch",
                    "pipeline": name,
                    "profile_id": record["profile_id"],
                    "expected": after.get("processors"),
                    "live": live.get("processors"),
                }
            )

    return {"drift": drift, "active": active_records}


# -- audit ----------------------------------------------------------------------


def run_audit(
    profile_id: Optional[str] = None,
    *,
    execer: Any = None,
    ledger_dir: Optional[Path] = None,
) -> dict[str, Any]:
    """M7 — sample agent-reachable payloads and flag a harness leak (O6).

    Live-only: needs the stack. The decision half this calls
    (`chaos.audit.audit_payloads`) is pinned by the unit suite; this
    sampling half is not. Always runs the positive control (inject a known
    canary, confirm it is flagged, remove it) so a clean pass is never
    vacuous. A sample that could not be taken is reported in `errors`, not
    silently left out of the sample.
    """
    execer = execer if execer is not None else DockerExecSeam()
    ledger_dir = Path(ledger_dir) if ledger_dir is not None else DEFAULT_LEDGER_DIR

    records = ledger_mod.read_records(ledger_dir)
    active = [r for r in records if not r.get("reverted_at")]
    if profile_id is not None:
        active = [r for r in active if r["profile_id"] == profile_id]

    payloads: list[dict[str, Any]] = []
    errors: list[str] = []

    def sample(what: str, fn: Any) -> Any:
        try:
            return fn()
        except SeamError as exc:
            errors.append(f"{what}: {exc}")
            return None

    health = sample("GET /health", lambda: execer.cmdb_request("GET", "/health"))
    if isinstance(health, dict):
        payloads.append(health)
    hosts_payload = sample("GET /hosts", lambda: execer.cmdb_request("GET", "/hosts"))
    if isinstance(hosts_payload, dict):
        payloads.extend(hosts_payload.get("hosts") or [])

    for record in active:
        if record["mode"] not in ("schema-drift", "data-drop"):
            continue
        for m in record["resolved_mutations"]:
            stream = m.get("target_stream", "logs-system.auth-*")
            # Newest documents first, from the window the fault was live in:
            # a leak stamped on a fresh document is what we're looking for,
            # and an unsorted sample would return the stream's oldest.
            since = record.get("activated_at")
            query: dict[str, Any] = (
                {"range": {"@timestamp": {"gte": since}}} if since else {"match_all": {}}
            )
            body = {"query": query, "size": 50, "sort": [{"@timestamp": {"order": "desc"}}]}
            result = sample(f"search {stream}", lambda: execer.es_request("POST", f"/{stream}/_search", body))
            if isinstance(result, dict):
                hits = (result.get("hits") or {}).get("hits") or []
                payloads.extend(h.get("_source", h) for h in hits)

    findings = audit_payloads(payloads)

    canary_host = "audit-canary-host"
    canary_caught = False
    try:
        execer.cmdb_request("POST", f"/admin/overlay/{canary_host}", {"owner": "chaos-harness-canary"})
        canary_payload = execer.cmdb_request("GET", f"/hosts/{canary_host}")
        canary_caught = bool(audit_payloads([canary_payload]))
    except SeamError as exc:
        errors.append(f"canary control: {exc}")
    try:
        execer.cmdb_request("DELETE", f"/admin/overlay/{canary_host}")
    except SeamError as exc:
        # A failed cleanup leaves a literal "chaos-harness-canary" marker
        # live in the CMDB — exactly the kind of leak this audit exists to
        # catch, so it belongs in `findings`, not swallowed.
        findings.append(
            f"canary control cleanup failed: could not remove the {canary_host!r} overlay — {exc}"
        )

    return {
        "findings": findings,
        "canary_control_passed": canary_caught,
        "sampled": len(payloads),
        "errors": errors,
    }


# -- CLI --------------------------------------------------------------------


def _cli_list(_args: argparse.Namespace) -> int:
    for profile_id in list_profiles(profiles_dir=DEFAULT_PROFILES_DIR):
        print(profile_id)
    return 0


def _cli_plan(args: argparse.Namespace) -> int:
    print(json.dumps(plan(args.profile, seed=args.seed), indent=2, default=str))
    return 0


def _cli_activate(args: argparse.Namespace) -> int:
    record = activate(args.profile, seed=args.seed)
    print(json.dumps(record, indent=2, default=str))
    return 0


def _cli_revert(args: argparse.Namespace) -> int:
    if args.all:
        reverted, failed = revert_all()
        for record in reverted:
            print(f"reverted {record['ledger_ref']} ({record['profile_id']})")
        for ref, error in failed.items():
            print(f"FAILED  {ref}: {error}", file=sys.stderr)
        print(f"reverted {len(reverted)} of {len(reverted) + len(failed)} active profile(s)")
        return 1 if failed else 0
    if not args.ledger_ref:
        print("revert needs a ledger_ref, or --all", file=sys.stderr)
        return 2
    print(json.dumps(revert(args.ledger_ref), indent=2, default=str))
    return 0


def _cli_status(_args: argparse.Namespace) -> int:
    result = status()
    print(json.dumps(result, indent=2, default=str))
    return 1 if result["drift"] else 0


def audit_is_clean(result: dict[str, Any]) -> bool:
    """A clean report is only clean if the positive control fired and every
    sample was actually taken — an audit that inspected nothing is not a
    pass."""
    return not result["findings"] and bool(result["canary_control_passed"]) and not result["errors"]


def _cli_audit(args: argparse.Namespace) -> int:
    result = run_audit(args.profile)
    print(json.dumps(result, indent=2, default=str))
    return 0 if audit_is_clean(result) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Chaos control plane for the SOC playground")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list available chaos profiles")

    pplan = sub.add_parser("plan", help="resolve a profile into the mutations activate would push")
    pplan.add_argument("profile")
    pplan.add_argument("--seed", type=int, default=None)

    pact = sub.add_parser("activate", help="activate a chaos profile")
    pact.add_argument("profile")
    pact.add_argument("--seed", type=int, default=None)

    prev = sub.add_parser("revert", help="revert an active chaos profile")
    prev.add_argument("ledger_ref", nargs="?")
    prev.add_argument("--all", action="store_true", help="revert every active profile")

    sub.add_parser("status", help="reconcile the ledger against live state (exit 1 on drift)")

    paud = sub.add_parser("audit", help="scan agent-reachable payloads for a harness leak")
    paud.add_argument("profile", nargs="?", help="restrict to this profile's own mutations")

    args = parser.parse_args()
    handlers = {
        "list": _cli_list,
        "plan": _cli_plan,
        "activate": _cli_activate,
        "revert": _cli_revert,
        "status": _cli_status,
        "audit": _cli_audit,
    }
    try:
        return handlers[args.command](args)
    except SeamError as exc:
        print(f"stack unreachable or refused the request: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
