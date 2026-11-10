#!/usr/bin/env python3
"""Capture one freeze of the playground at T (#1347 O1): a set of parts and `freeze.yaml`.

Operator-run, one freeze per run, no fault active, under the lab-server capture lock (D14):

    refuse a T already past or too near for the scenarios -> take the lock -> refuse on an active
    fault -> refuse a snapshot name already taken -> check the snapshot repository -> hold off the
    alert-ticket watcher -> fire the scenario batch across [T - max_age, T] -> wait until T ->
    process trees, stub dumps, detection rules, host commits, volume copies -> refresh and snapshot
    Elasticsearch -> resume the pickups, release the lock -> verification
    restore (per-index counts) -> write the parts and freeze.yaml

The lock and the hold-off last the whole batch, at least `MAX_AGE` (A9). All-or-nothing: any
failure removes the partial parts, deletes the snapshot this run created (never one that was
already there), frees the lock and resumes the pickups, and writes no freeze.yaml. The operator
registers the snapshot repository once; capture only verifies it.

The index patterns are the lab tenant's (`settings/systems/elastic/config.env` under
`$V2_FROZEN_TENANT_DIR`: `ELASTIC_EVENTS_INDEX`, `ELASTIC_ALERTS_INDEX`) and are
recorded in freeze.yaml as `patterns: [events, alerts]` (D24).

    python3 playground-v2/scripts/capture_case.py <held_out>/freezes/<freeze-id> \\
        --repository frozen-cases [--scenario <id> ...] [--T <iso>] --parts-dir <lab disk path>

The parts' bytes go under `<parts-dir>/<freeze-id>/` (D8); git holds only freeze.yaml. `ops=`,
`es=`, `lock_store=` and `clock=` are injectable so tests never need the live stack. `ops` is the
lab's operations object (`lab_ops.py`); the calls capture makes are listed on `capture`.
"""
from __future__ import annotations

import argparse
import getpass
import os
import shutil
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
for _path in (HERE, HERE.parent):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import frozen_copy  # noqa: E402
from chaos import lock  # noqa: E402
from make_case import MAX_AGE  # noqa: E402

LEAD = timedelta(minutes=15)  # the last scenario fires this long before T, so its alert exists at T
MARGIN = timedelta(minutes=1)  # the default T without scenarios: far enough ahead to still be ahead at start
POLL_S = 30.0
IN_PROGRESS = ("IN_PROGRESS", "STARTED")


class CaptureRefused(RuntimeError):
    """The lab is not in a state to capture (an active fault, an existing freeze)."""


class SnapshotFailed(RuntimeError):
    """The snapshot did not end in SUCCESS."""


def _fire_times(T: datetime, count: int) -> list[datetime]:
    """`count` moments spread evenly over [T - MAX_AGE, T - LEAD], the first at the window's start."""
    start, end = T - MAX_AGE, T - LEAD
    if count == 1:
        return [start]
    return [start + (end - start) * i / (count - 1) for i in range(count)]


def _verify_repository(es: Any, repository: str) -> None:
    """Raises when the operator has not registered `repository` (or it cannot write)."""
    es.es_request("POST", f"/_snapshot/{repository}/_verify")


def _snapshot_exists(es: Any, repository: str, name: str) -> bool:
    try:
        found = es.es_request("GET", f"/_snapshot/{repository}/{name}?ignore_unavailable=true")
    except Exception:  # noqa: BLE001 - a missing snapshot may be a 404; any other fault fails the PUT too
        return False
    return bool(found.get("snapshots"))


def _create_snapshot(es: Any, repository: str, name: str, patterns: list[str]) -> None:
    es.es_request("PUT", f"/_snapshot/{repository}/{name}?wait_for_completion=false",
                  {"indices": list(patterns), "include_global_state": False})


def _await_snapshot(es: Any, clock: Any, repository: str, name: str) -> dict:
    """Wait for the snapshot `name` to end and return its record."""
    while True:
        record = es.es_request("GET", f"/_snapshot/{repository}/{name}")["snapshots"][0]
        if record.get("state") not in IN_PROGRESS:
            break
        clock.sleep(POLL_S)
    if record.get("state") != "SUCCESS":
        raise SnapshotFailed(f"snapshot {name} ended {record.get('state')}, not SUCCESS: "
                             f"{record.get('failures') or record.get('reason') or ''}")
    return record




def _take_parts(ops: Any, staging: Path) -> dict[str, str]:
    """Take every part into `staging`; return {part name: sha256 hex}. Hosts are paused by their
    commits, so those and the volume copies come after the cheap parts."""
    names: list[str] = []
    for take in (ops.proc_tree, ops.stub_dumps, ops.detection_rules, ops.commit_hosts, ops.copy_volumes):
        names += take(staging)
    if len(set(names)) != len(names):
        raise RuntimeError(f"two parts share a name: {sorted(names)}")
    return {name: frozen_copy.sha256_file(staging / name) for name in names}


def _under_lock(ops: Any, es: Any, clock: Any, token: str, *, T: datetime, scenarios: list[str],
                patterns: list[str], repository: str, name: str, staging: Path,
                started: list[str]) -> tuple[dict[str, str], dict]:
    """Everything that needs the lock. Appends "pickups" to `started` once they are held off, and
    "snapshot" once this run's PUT has succeeded (so the snapshot is its own to delete), and the
    caller undoes exactly what ran."""
    if faults := ops.active_faults():
        raise CaptureRefused(f"a fault is active: {', '.join(map(str, faults))}; revert it first")
    if _snapshot_exists(es, repository, name):
        raise CaptureRefused(f"snapshot {repository}:{name} already exists; capture never "
                             "overwrites or deletes a snapshot it did not create")
    _verify_repository(es, repository)
    started.append("pickups")
    ops.hold_pickups()
    for scenario, at in zip(scenarios, _fire_times(T, len(scenarios)), strict=True):
        clock.sleep_until(at)
        ops.fire(scenario, token)
    clock.sleep_until(T)
    parts = _take_parts(ops, staging)
    es.es_request("POST", "/" + ",".join(patterns) + "/_refresh")
    _create_snapshot(es, repository, name, patterns)
    started.append("snapshot")
    return parts, _await_snapshot(es, clock, repository, name)


def _delete_snapshot(es: Any, repository: str, name: str) -> None:
    try:
        es.es_request("DELETE", f"/_snapshot/{repository}/{name}")
    except Exception as exc:  # the snapshot may never have been created; the original error wins
        print(f"could not delete snapshot {name}: {exc}", file=sys.stderr)


def _publish(freeze_dir: Path, parts_root: Path, staging: Path, doc: dict) -> None:
    """Move the staged parts into place, then write freeze.yaml last; undo the move on failure."""
    parts_root.parent.mkdir(parents=True, exist_ok=True)
    staging.rename(parts_root)
    try:
        freeze_dir.mkdir(parents=True, exist_ok=True)
        tmp = freeze_dir / ".freeze.yaml.tmp"
        tmp.write_text(yaml.safe_dump(doc, sort_keys=False))
        os.replace(tmp, freeze_dir / "freeze.yaml")
    except BaseException:
        shutil.rmtree(parts_root, ignore_errors=True)
        (freeze_dir / ".freeze.yaml.tmp").unlink(missing_ok=True)
        raise


def _check_moment(T: datetime, scenarios: list[str], now: datetime) -> None:
    """T is not before this capture's start; with scenarios it leaves MAX_AGE to fire them in."""
    if T < now:
        raise CaptureRefused(f"T {frozen_copy.stamp(T)} is already past ({frozen_copy.stamp(now)}): pick a later T")
    if scenarios and T - now < MAX_AGE:
        raise CaptureRefused(f"T leaves less than {MAX_AGE} for the scenario batch: pick a later T")


def capture(freeze_dir: Path, *, T: datetime, scenarios: list[str], repository: str,
            tenant_settings: Path, ops: Any, es: Any, lock_store: Any, parts_dir: Path, clock: Any,
            captured_by: str) -> dict:
    """Capture the freeze `freeze_dir.name` at `T`; returns the freeze.yaml document.

    `tenant_settings` is the lab tenant's `settings/` directory: the freeze's patterns are its
    events and alerts patterns (D24). `es` is the LIVE cluster
    (`es_request(method, path, body=None)`). `ops` is called as:
    active_faults() -> list; hold_pickups(); release_pickups(); fire(scenario, lock_token);
    proc_tree(dest), stub_dumps(dest), detection_rules(dest), commit_hosts(dest),
    copy_volumes(dest) -> part names written under dest; verify_restore(repository, snapshot)
    -> {index: count}.
    """
    freeze_dir, parts_dir = Path(freeze_dir), Path(parts_dir)
    freeze_id = freeze_dir.name
    if (freeze_dir / "freeze.yaml").exists():
        raise CaptureRefused(f"freeze {freeze_id} already exists; a freeze is never overwritten")
    patterns = frozen_copy.tenant_patterns(tenant_settings)
    _check_moment(T, scenarios, clock.now())
    token = lock.take(lock_store, lock.CAPTURE)
    started: list[str] = []
    staging: Path | None = None
    try:
        try:
            parts_dir.mkdir(parents=True, exist_ok=True)
            staging = Path(tempfile.mkdtemp(prefix=f".{freeze_id}.", dir=parts_dir))
            parts, snap = _under_lock(ops, es, clock, token, T=T, scenarios=scenarios,
                                      patterns=patterns, repository=repository, name=freeze_id,
                                      staging=staging, started=started)
        finally:
            try:
                if "pickups" in started:
                    ops.release_pickups()
            finally:
                lock.release(lock_store, lock.CAPTURE, token)
    except BaseException:
        if "snapshot" in started:
            _delete_snapshot(es, repository, freeze_id)
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        raise

    try:
        counts = ops.verify_restore(repository, snap["snapshot"])
        doc = {"T": frozen_copy.stamp(T),
               "elastic": {"repository": repository, "snapshot": snap["snapshot"],
                           "uuid": snap["uuid"], "indices": dict(counts)},
               "patterns": list(patterns), "parts": parts, "captured_by": captured_by}
        _publish(freeze_dir, parts_dir / freeze_id, staging, doc)
    except BaseException:
        _delete_snapshot(es, repository, freeze_id)
        shutil.rmtree(staging, ignore_errors=True)
        raise
    print(f"captured {freeze_id} at {doc['T']}: {len(parts)} parts, "
          f"{sum(counts.values())} documents in {len(counts)} indices")
    return doc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture a freeze of the playground at T")
    parser.add_argument("freeze_dir", type=Path, help="held_out/freezes/<freeze-id> (its name is the id)")
    parser.add_argument("--repository", required=True, help="the registered snapshot repository")
    parser.add_argument("--scenario", action="append", default=[], dest="scenarios",
                        help="an attack scenario to fire across the window before T (repeat)")
    parser.add_argument("--T", dest="T", default=None,
                        help="the freeze moment (ISO, UTC); default: just ahead of now, or now + max age "
                             "with scenarios")
    parser.add_argument("--parts-dir", type=Path, default=os.environ.get("V2_FROZEN_PARTS_DIR"),
                        help="the lab disk path parts live under (D8); default $V2_FROZEN_PARTS_DIR")
    parser.add_argument("--captured-by", default=getpass.getuser())
    args = parser.parse_args(argv)
    if not args.parts_dir:
        parser.error("--parts-dir is required (or $V2_FROZEN_PARTS_DIR)")
    moment = (frozen_copy.utc(args.T) if args.T
              else datetime.now(UTC) + (MAX_AGE + LEAD if args.scenarios else MARGIN))
    from chaos.ctl import DockerExecSeam
    from lab_ops import LabOps
    try:
        capture(args.freeze_dir, T=moment, scenarios=args.scenarios, repository=args.repository,
                tenant_settings=frozen_copy.tenant_settings_dir(), ops=LabOps.from_environment(),
                es=DockerExecSeam(), lock_store=lock.DockerLockStore(), parts_dir=args.parts_dir,
                clock=frozen_copy.WallClock(), captured_by=args.captured_by)
    except (lock.LockError, CaptureRefused, frozen_copy.CopyRefused) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
