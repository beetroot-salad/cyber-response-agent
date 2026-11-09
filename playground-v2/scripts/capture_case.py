#!/usr/bin/env python3
"""Capture one freeze of the playground at T (#1347 O1): a set of parts and `freeze.yaml`.

Operator-run, one freeze per run, no fault active, under the lab-server capture lock (D14):

    take the lock -> refuse on an active fault -> check the snapshot repository -> hold off the
    alert-ticket watcher and live pickups -> fire the scenario batch across [T - max_age, T] ->
    wait until T -> process trees, stub dumps, detection rules, host commits, volume copies ->
    refresh and snapshot Elasticsearch -> resume the pickups, release the lock -> verification
    restore (per-index counts) -> write the parts and freeze.yaml

The lock and the hold-off last the whole batch, at least `MAX_AGE` (A9). All-or-nothing: any
failure removes the partial parts, deletes the snapshot this run wrote, frees the lock and
resumes the pickups, and writes no freeze.yaml. The operator registers the snapshot repository
once; capture only verifies it.

    python3 playground-v2/scripts/capture_case.py <held_out>/freezes/<freeze-id> \\
        --repository frozen-cases --pattern 'logs-*' --pattern '.internal.alerts-security.alerts-default-*' \\
        [--scenario <id> ...] [--T <iso>] --parts-dir <lab disk path>

The parts' bytes go under `<parts-dir>/<freeze-id>/` (D8); git holds only freeze.yaml. `ops=`,
`es=`, `lock_store=` and `clock=` are injectable so tests never need the live stack. `ops` is the
lab's operations object (`lab_ops.py`); the calls capture makes are listed on `capture`.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import shutil
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
for _path in (HERE, HERE.parent):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from chaos import lock  # noqa: E402
from make_case import MAX_AGE  # noqa: E402

LEAD = timedelta(minutes=15)  # the last scenario fires this long before T, so its alert exists at T
POLL_S = 30.0
IN_PROGRESS = ("IN_PROGRESS", "STARTED")


class CaptureRefused(RuntimeError):
    """The lab is not in a state to capture (an active fault, an existing freeze)."""


class SnapshotFailed(RuntimeError):
    """The snapshot did not end in SUCCESS."""


class WallClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def sleep_until(self, moment: datetime) -> None:
        while (left := (moment - self.now()).total_seconds()) > 0:
            time.sleep(min(left, 60.0))


def stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fire_times(T: datetime, count: int) -> list[datetime]:
    """`count` moments spread evenly over [T - MAX_AGE, T - LEAD], the first at the window's start."""
    start, end = T - MAX_AGE, T - LEAD
    if count == 1:
        return [start]
    return [start + (end - start) * i / (count - 1) for i in range(count)]


def _verify_repository(es: Any, repository: str) -> None:
    """Raises when the operator has not registered `repository` (or it cannot write)."""
    es.es_request("POST", f"/_snapshot/{repository}/_verify")


def _snapshot(es: Any, clock: Any, repository: str, name: str, patterns: list[str]) -> dict:
    """Snapshot `patterns` into `repository` as `name`, wait for it, and return its record."""
    es.es_request("PUT", f"/_snapshot/{repository}/{name}?wait_for_completion=false",
                  {"indices": list(patterns), "include_global_state": False})
    while True:
        record = es.es_request("GET", f"/_snapshot/{repository}/{name}")["snapshots"][0]
        if record.get("state") not in IN_PROGRESS:
            break
        clock.sleep(POLL_S)
    if record.get("state") != "SUCCESS":
        raise SnapshotFailed(f"snapshot {name} ended {record.get('state')}, not SUCCESS: "
                             f"{record.get('failures') or record.get('reason') or ''}")
    return record


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _take_parts(ops: Any, staging: Path) -> dict[str, str]:
    """Take every part into `staging`; return {part name: sha256 hex}. Hosts are paused by their
    commits, so those and the volume copies come after the cheap parts."""
    names: list[str] = []
    for take in (ops.proc_tree, ops.stub_dumps, ops.detection_rules, ops.commit_hosts, ops.copy_volumes):
        names += take(staging)
    if len(set(names)) != len(names):
        raise RuntimeError(f"two parts share a name: {sorted(names)}")
    return {name: _sha256(staging / name) for name in names}


def _under_lock(ops: Any, es: Any, clock: Any, token: str, *, T: datetime, scenarios: list[str],
                patterns: list[str], repository: str, name: str, staging: Path,
                started: list[str]) -> tuple[dict[str, str], dict]:
    """Everything that needs the lock. Appends "pickups" to `started` once they are held off, and
    "snapshot" once the snapshot may exist, so the caller undoes exactly what ran."""
    if faults := ops.active_faults():
        raise CaptureRefused(f"a fault is active: {', '.join(map(str, faults))}; revert it first")
    _verify_repository(es, repository)
    started.append("pickups")
    ops.hold_pickups()
    if scenarios and clock.now() > T - MAX_AGE:
        raise CaptureRefused(f"T leaves less than {MAX_AGE} for the scenario batch: pick a later T")
    for scenario, at in zip(scenarios, _fire_times(T, len(scenarios)), strict=True):
        clock.sleep_until(at)
        ops.fire(scenario, token)
    clock.sleep_until(T)
    parts = _take_parts(ops, staging)
    es.es_request("POST", "/" + ",".join(patterns) + "/_refresh")
    started.append("snapshot")
    return parts, _snapshot(es, clock, repository, name, patterns)


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


def capture(freeze_dir: Path, *, T: datetime, scenarios: list[str], patterns: list[str],
            repository: str, ops: Any, es: Any, lock_store: Any, parts_dir: Path, clock: Any,
            captured_by: str) -> dict:
    """Capture the freeze `freeze_dir.name` at `T`; returns the freeze.yaml document.

    `es` is the LIVE cluster (`es_request(method, path, body=None)`). `ops` is called as:
    active_faults() -> list; hold_pickups(); release_pickups(); fire(scenario, lock_token);
    proc_tree(dest), stub_dumps(dest), detection_rules(dest), commit_hosts(dest),
    copy_volumes(dest) -> part names written under dest; verify_restore(repository, snapshot)
    -> {index: count}.
    """
    freeze_dir, parts_dir = Path(freeze_dir), Path(parts_dir)
    freeze_id = freeze_dir.name
    if (freeze_dir / "freeze.yaml").exists():
        raise CaptureRefused(f"freeze {freeze_id} already exists; a freeze is never overwritten")
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
        doc = {"T": stamp(T),
               "elastic": {"repository": repository, "snapshot": snap["snapshot"],
                           "uuid": snap["uuid"], "indices": dict(counts)},
               "parts": parts, "captured_by": captured_by}
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
    parser.add_argument("--pattern", action="append", required=True, dest="patterns",
                        help="an events or alerts index pattern to snapshot (repeat)")
    parser.add_argument("--scenario", action="append", default=[], dest="scenarios",
                        help="an attack scenario to fire across the window before T (repeat)")
    parser.add_argument("--T", dest="T", default=None,
                        help="the freeze moment (ISO, UTC); default: now, or now + max age with scenarios")
    parser.add_argument("--parts-dir", type=Path, default=os.environ.get("V2_FROZEN_PARTS_DIR"),
                        help="the lab disk path parts live under (D8); default $V2_FROZEN_PARTS_DIR")
    parser.add_argument("--captured-by", default=getpass.getuser())
    args = parser.parse_args(argv)
    if not args.parts_dir:
        parser.error("--parts-dir is required (or $V2_FROZEN_PARTS_DIR)")
    moment = (datetime.fromisoformat(args.T.replace("Z", "+00:00")).astimezone(UTC) if args.T
              else datetime.now(UTC) + (MAX_AGE + LEAD if args.scenarios else timedelta(0)))
    from chaos.ctl import DockerExecSeam
    from lab_ops import LabOps
    try:
        capture(args.freeze_dir, T=moment, scenarios=args.scenarios, patterns=args.patterns,
                repository=args.repository, ops=LabOps.from_environment(), es=DockerExecSeam(),
                lock_store=lock.DockerLockStore(), parts_dir=args.parts_dir, clock=WallClock(),
                captured_by=args.captured_by)
    except (lock.LockError, CaptureRefused) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
