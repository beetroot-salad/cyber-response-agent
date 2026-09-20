#!/usr/bin/env python3
"""M1 — the chaos control plane: `list`, `activate`, `revert`, `status`, `audit`.

Every mutation travels over `docker --context soc-playground exec`
(`DockerExecSeam`) — CMDB via a `python3 -c <urllib>` round trip, Elasticsearch
via `curl` inside the `elasticsearch` container. No path from outside the
containers, and no long-lived controller process — the two properties that
keep the controller itself out of the telemetry the agent-under-test reads
(O7).

`activate`/`revert`/`status` all take an injectable `execer=` so tests never
need the live stack — see chaos/tests/_fakes.py:FakeExecSeam. The functions
also take explicit `profiles_dir=`/`rules_dir=`/`ledger_dir=` for the same
reason; omitted, they default to this package's own committed locations, and
that is the path `attacks/runner.py`'s `--chaos` flag drives.
"""
from __future__ import annotations

import argparse
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
from chaos.guard import check_profile  # noqa: E402
from chaos.mutations import resolve_mutations  # noqa: E402
from chaos.profiles import list_profiles, load_profile  # noqa: E402

DEFAULT_PROFILES_DIR = HERE / "profiles"
DEFAULT_RULES_DIR = HERE.parent / "detection-rules"
DEFAULT_LEDGER_DIR = HERE / "ledger"
DEFAULT_INVENTORY_PATH = HERE.parent / "hosts" / "inventory.yaml"

DOCKER_CONTEXT = "soc-playground"
BAKED_INVENTORY_PATH = "/opt/cmdb/inventory.yaml"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_ref() -> str:
    return f"chaos-{uuid.uuid4().hex[:12]}"


def _fingerprint(mutations: list[dict[str, Any]]) -> str:
    blob = json.dumps(mutations, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _read_inventory(inventory_path: Optional[Path] = None) -> dict[str, Any]:
    path = Path(inventory_path) if inventory_path is not None else DEFAULT_INVENTORY_PATH
    return yaml.safe_load(path.read_text())


class DockerExecSeam:
    """The real exec seam. Nothing else in this module talks to the stack.

    Every call shells `docker --context soc-playground exec` into the target
    container itself; there is no host-side network path to the stub or to
    Elasticsearch (O7 — a direct host-side HTTP call would show up as a
    gateway-IP flow in the agent's own Zeek telemetry, which is exactly what
    keeps the controller invisible to the agent-under-test). `run=` is an
    injection seam over `subprocess.run` so a test can assert on the argv
    without actually shelling out — see chaos/tests/test_m1_real_seam.py.
    """

    def __init__(self, run: Any = subprocess.run) -> None:
        self._run = run

    def cmdb_request(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        script = (
            "import json, sys, urllib.request, urllib.error\n"
            f"req = urllib.request.Request('http://127.0.0.1:8080{path}', method={method.upper()!r})\n"
            "raw = sys.stdin.read()\n"
            "if raw:\n"
            "    req.data = raw.encode()\n"
            "    req.add_header('Content-Type', 'application/json')\n"
            "try:\n"
            "    with urllib.request.urlopen(req, timeout=10) as resp:\n"
            "        sys.stdout.write(resp.read().decode())\n"
            "except urllib.error.HTTPError as e:\n"
            "    sys.stdout.write(e.read().decode())\n"
            "    sys.exit(e.code if e.code < 256 else 1)\n"
        )
        payload = json.dumps(body) if body is not None else ""
        args = [
            "docker", "--context", DOCKER_CONTEXT, "exec", "-i",
            "cmdb", "python3", "-c", script,
        ]
        proc = self._run(args, input=payload, capture_output=True, text=True)
        return self._parse(proc)

    def es_request(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        parts = ["curl", "-s", "-k", "-u", "elastic:$ELASTIC_PASSWORD", "-X", method.upper(),
                 f"https://localhost:9200{path}"]
        if body is not None:
            parts += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
        quoted = " ".join(
            '"elastic:$ELASTIC_PASSWORD"' if part == "elastic:$ELASTIC_PASSWORD" else shlex.quote(part)
            for part in parts
        )
        args = ["docker", "--context", DOCKER_CONTEXT, "exec", "elasticsearch", "bash", "-lc", quoted]
        proc = self._run(args, capture_output=True, text=True)
        return self._parse(proc)

    def read_container_file(self, container: str, path: str) -> str:
        args = ["docker", "--context", DOCKER_CONTEXT, "exec", container, "cat", path]
        proc = self._run(args, capture_output=True, text=True)
        if proc.returncode != 0:
            raise FileNotFoundError(f"{container}:{path}: {proc.stderr.strip()}")
        return proc.stdout

    @staticmethod
    def _parse(proc: "subprocess.CompletedProcess[str]") -> tuple[int, Any]:
        text = proc.stdout.strip()
        if not text:
            return proc.returncode, {}
        try:
            return proc.returncode, json.loads(text)
        except json.JSONDecodeError:
            return proc.returncode, {"raw": text}


class ChaosApplyError(RuntimeError):
    """A mutation did not reach the stack — nothing about it may be recorded
    as ground truth (O5): a failed injection is not an injection."""


def _apply_mutations(mode: str, mutations: list[dict[str, Any]], execer: Any) -> None:
    # A multi-mutation profile (hosts: >1) can fail partway through. Track
    # what actually landed and roll it back on failure — otherwise a partial
    # success is left live on the stack with no ledger record pointing at it
    # (activate() only writes the record after this returns cleanly), which
    # neither `status` nor `revert --all` can ever find.
    applied: list[dict[str, Any]] = []
    try:
        if mode == "cmdb-stale":
            for m in mutations:
                body = {m["field"]: m["new_value"]} if m["kind"] == "field-flip" else m["new_value"]
                rc, resp = execer.cmdb_request("POST", f"/admin/overlay/{m['host']}", body)
                if rc != 0:
                    raise ChaosApplyError(f"POST /admin/overlay/{m['host']} failed rc={rc}: {resp}")
                applied.append(m)
        else:
            for m in mutations:
                rc, resp = execer.es_request(
                    "PUT", f"/_ingest/pipeline/{m['pipeline']}", {"processors": [m["processor"]]}
                )
                if rc != 0:
                    raise ChaosApplyError(f"PUT /_ingest/pipeline/{m['pipeline']} failed rc={rc}: {resp}")
                applied.append(m)
    except ChaosApplyError:
        if applied:
            try:
                _undo_mutations(mode, applied, execer)
            except ChaosApplyError:
                pass  # best effort — the original failure is what activate() raises
        raise


def _undo_mutations(mode: str, mutations: list[dict[str, Any]], execer: Any) -> None:
    # Best-effort: attempt every undo before raising, so one failed DELETE
    # doesn't strand the others live. A revert failure is still surfaced —
    # never swallowed — so it isn't mistaken for a clean revert.
    errors: list[str] = []
    if mode == "cmdb-stale":
        for m in mutations:
            rc, resp = execer.cmdb_request("DELETE", f"/admin/overlay/{m['host']}")
            if rc != 0:
                errors.append(f"DELETE /admin/overlay/{m['host']} failed rc={rc}: {resp}")
    else:
        seen: set[str] = set()
        for m in mutations:
            if m["pipeline"] in seen:
                continue
            seen.add(m["pipeline"])
            rc, resp = execer.es_request("DELETE", f"/_ingest/pipeline/{m['pipeline']}")
            if rc != 0:
                errors.append(f"DELETE /_ingest/pipeline/{m['pipeline']} failed rc={rc}: {resp}")
    if errors:
        raise ChaosApplyError("; ".join(errors))


def activate(
    profile_id: str,
    *,
    seed: Optional[int] = None,
    execer: Any = None,
    profiles_dir: Optional[Path] = None,
    rules_dir: Optional[Path] = None,
    ledger_dir: Optional[Path] = None,
    inventory_path: Optional[Path] = None,
) -> dict[str, Any]:
    execer = execer if execer is not None else DockerExecSeam()
    profiles_dir = Path(profiles_dir) if profiles_dir is not None else DEFAULT_PROFILES_DIR
    rules_dir = Path(rules_dir) if rules_dir is not None else DEFAULT_RULES_DIR
    ledger_dir = Path(ledger_dir) if ledger_dir is not None else DEFAULT_LEDGER_DIR

    profile = load_profile(profile_id, profiles_dir=profiles_dir)
    # The guard is a precondition, not a report: nothing below this line runs
    # until it clears, so a refused profile mutates nothing (O4).
    check_profile(profile, rules_dir=rules_dir)

    effective_seed = seed if seed is not None else profile.seed
    inventory = _read_inventory(inventory_path)
    mutations = resolve_mutations(profile, seed=effective_seed, inventory=inventory)
    _apply_mutations(profile.mode, mutations, execer)

    record = {
        "ledger_ref": _new_ref(),
        "profile_id": profile.id,
        "seed": effective_seed,
        "mode": profile.mode,
        "resolved_mutations": mutations,
        "activated_at": _now_iso(),
        "live_fingerprint": _fingerprint(mutations),
    }
    ledger_mod.write_record(ledger_dir, record)
    return record


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

    _undo_mutations(record["mode"], record["resolved_mutations"], execer)
    record["reverted_at"] = _now_iso()
    ledger_mod.write_record(ledger_dir, record)
    return record


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
    ledger) — so this never trusts the ledger alone.
    """
    execer = execer if execer is not None else DockerExecSeam()
    ledger_dir = Path(ledger_dir) if ledger_dir is not None else DEFAULT_LEDGER_DIR

    records = ledger_mod.read_records(ledger_dir)
    active_records = [r for r in records if not r.get("reverted_at")]

    # The *baked* inventory (the container's own copy), not the working-tree
    # file, which can drift from the image.
    baked = yaml.safe_load(execer.read_container_file("cmdb", BAKED_INVENTORY_PATH)) or {}
    baked_hosts = {h["name"]: h for h in baked.get("hosts") or []}

    rc, hosts_payload = execer.cmdb_request("GET", "/hosts")
    live_hosts = (
        {h["name"]: h for h in (hosts_payload.get("hosts") or [])}
        if rc == 0 and isinstance(hosts_payload, dict)
        else {}
    )

    drift: list[dict[str, Any]] = []
    expected_pipelines: dict[str, str] = {}  # pipeline name -> owning profile_id

    # The reconciled expectation: baked inventory, with every active
    # cmdb-stale record's mutations applied on top. Diffing *this* against
    # live — rather than only checking each record's own claimed mutation —
    # is what catches drift the ledger never predicted: a stray overlay
    # nobody's ledger entry explains is exactly the asymmetric-persistence
    # case M5 exists to catch, and a ledger-only check can't see it when the
    # ledger itself is what went stale (e.g. lost on a restart, or simply
    # empty because the mutation was made by hand).
    expected_hosts: dict[str, dict[str, Any]] = {name: dict(rec) for name, rec in baked_hosts.items()}
    # (host, field) -> owning record, for attributing a mismatch; "*" means
    # "this host's very presence/absence is owned by this record".
    owner_of: dict[tuple[str, str], dict[str, Any]] = {}

    for record in active_records:
        if record["mode"] != "cmdb-stale":
            for m in record["resolved_mutations"]:
                expected_pipelines[m["pipeline"]] = record["profile_id"]
            continue
        for m in record["resolved_mutations"]:
            host = m["host"]
            if m["kind"] == "field-flip":
                expected_hosts.setdefault(host, dict(baked_hosts.get(host, {"name": host})))
                expected_hosts[host][m["field"]] = m["new_value"]
                owner_of[(host, m["field"])] = record
                # The image itself can move independent of the overlay (a
                # rebuild) — catch the ledger's premise going stale.
                baked_value = baked_hosts.get(host, {}).get(m["field"])
                if baked_value != m["old_value"]:
                    drift.append(
                        {
                            "type": "baked-inventory-moved",
                            "profile_id": record["profile_id"],
                            "host": host,
                            "field": m["field"],
                            "ledger_old_value": m["old_value"],
                            "baked_value": baked_value,
                        }
                    )
            elif m["kind"] == "phantom-host":
                expected_hosts[host] = dict(m["new_value"])
                owner_of[(host, "*")] = record
            elif m["kind"] == "missing-host":
                expected_hosts.pop(host, None)
                owner_of[(host, "*")] = record

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

    rc, pipelines_payload = execer.es_request("GET", "/_ingest/pipeline/*@custom")
    live_pipelines = set(pipelines_payload) if rc == 0 and isinstance(pipelines_payload, dict) else set()

    for name in sorted(live_pipelines - set(expected_pipelines)):
        drift.append({"type": "stray-pipeline", "pipeline": name})
    for name in sorted(set(expected_pipelines) - live_pipelines):
        drift.append(
            {"type": "pipeline-missing", "pipeline": name, "profile_id": expected_pipelines[name]}
        )

    return {"drift": drift, "active": active_records}


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
    vacuous.
    """
    execer = execer if execer is not None else DockerExecSeam()
    ledger_dir = Path(ledger_dir) if ledger_dir is not None else DEFAULT_LEDGER_DIR

    records = ledger_mod.read_records(ledger_dir)
    active = [r for r in records if not r.get("reverted_at")]
    if profile_id is not None:
        active = [r for r in active if r["profile_id"] == profile_id]

    payloads: list[dict[str, Any]] = []
    rc, health = execer.cmdb_request("GET", "/health")
    if rc == 0 and isinstance(health, dict):
        payloads.append(health)
    rc, hosts_payload = execer.cmdb_request("GET", "/hosts")
    if rc == 0 and isinstance(hosts_payload, dict):
        payloads.extend(hosts_payload.get("hosts") or [])

    for record in active:
        if record["mode"] not in ("schema-drift", "data-drop"):
            continue
        for m in record["resolved_mutations"]:
            stream = m.get("target_stream", "logs-system.auth-*")
            rc, result = execer.es_request(
                "POST", f"/{stream}/_search", {"query": {"match_all": {}}, "size": 50}
            )
            if rc == 0 and isinstance(result, dict):
                hits = (result.get("hits") or {}).get("hits") or []
                payloads.extend(h.get("_source", h) for h in hits)

    findings = audit_payloads(payloads)

    canary_host = "audit-canary-host"
    execer.cmdb_request("POST", f"/admin/overlay/{canary_host}", {"owner": "chaos-harness-canary"})
    rc, canary_payload = execer.cmdb_request("GET", f"/hosts/{canary_host}")
    canary_caught = rc == 0 and bool(audit_payloads([canary_payload]))
    cleanup_rc, cleanup_resp = execer.cmdb_request("DELETE", f"/admin/overlay/{canary_host}")
    if cleanup_rc != 0:
        # A failed cleanup leaves a literal "chaos-harness-canary" marker
        # live in the CMDB — exactly the kind of leak this audit exists to
        # catch, so it belongs in `findings`, not swallowed.
        findings.append(
            f"canary control cleanup failed rc={cleanup_rc}: could not remove "
            f"the {canary_host!r} overlay — {cleanup_resp}"
        )

    return {"findings": findings, "canary_control_passed": canary_caught, "sampled": len(payloads)}


# -- CLI --------------------------------------------------------------------


def _cli_list(_args: argparse.Namespace) -> int:
    for profile_id in list_profiles(profiles_dir=DEFAULT_PROFILES_DIR):
        print(profile_id)
    return 0


def _cli_activate(args: argparse.Namespace) -> int:
    record = activate(args.profile, seed=args.seed)
    print(json.dumps(record, indent=2, default=str))
    return 0


def _cli_revert(args: argparse.Namespace) -> int:
    if args.all:
        active = [r for r in ledger_mod.read_records(DEFAULT_LEDGER_DIR) if not r.get("reverted_at")]
        for r in active:
            revert(r["ledger_ref"])
        print(f"reverted {len(active)} active profile(s)")
        return 0
    if not args.ledger_ref:
        print("revert needs a ledger_ref, or --all", file=sys.stderr)
        return 2
    print(json.dumps(revert(args.ledger_ref), indent=2, default=str))
    return 0


def _cli_status(_args: argparse.Namespace) -> int:
    print(json.dumps(status(), indent=2, default=str))
    return 0


def _cli_audit(args: argparse.Namespace) -> int:
    result = run_audit(args.profile)
    print(json.dumps(result, indent=2, default=str))
    return 0 if not result["findings"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Chaos control plane for the SOC playground")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list available chaos profiles")

    pact = sub.add_parser("activate", help="activate a chaos profile")
    pact.add_argument("profile")
    pact.add_argument("--seed", type=int, default=None)

    prev = sub.add_parser("revert", help="revert an active chaos profile")
    prev.add_argument("ledger_ref", nargs="?")
    prev.add_argument("--all", action="store_true", help="revert every active profile")

    sub.add_parser("status", help="reconcile the ledger against live state")

    paud = sub.add_parser("audit", help="scan agent-reachable payloads for a harness leak")
    paud.add_argument("profile", nargs="?", help="restrict to this profile's own mutations")

    args = parser.parse_args()
    handlers = {
        "list": _cli_list,
        "activate": _cli_activate,
        "revert": _cli_revert,
        "status": _cli_status,
        "audit": _cli_audit,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
