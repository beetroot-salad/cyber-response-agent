#!/usr/bin/env python3
"""Capture a held-out case's freeze (#1347 O1): the lab as of `as_of = alert + 1 h`.

Operator-run, one case at a time, under the lab-server capture lock (D9/D14):

    take the lock -> fire the scenario with the fault held -> wait for the alert -> wait until
    as_of -> proc-tree and stub dumps, then host commits and volume copies -> revert the fault
    -> settle -> read captured_at from Elasticsearch, refresh, fingerprint -> write the parts and
    freeze.yaml -> release the lock

All-or-nothing: any failure reverts the fault, releases the lock, removes the partial parts and
writes no freeze.yaml. A failed revert keeps the lock held, since the fault may still be live;
the operator reverts it (`chaos/ctl.py revert --all`) and clears the lock (`chaos/lock.py clear
capture`).

The parts' bytes go under `<parts-dir>/<slug>/` on the lab disk (D8); git holds only
freeze.yaml beside ground_truth.yaml. `confirmed` is left empty: the operator fills it after
labelling against a reference run (`launch_frozen.py --reference`).

    defender/.venv/bin/python playground-v2/scripts/capture_case.py \\
        evaluations/fixtures/held_out/<slug> --scenario <id> --rule <rule_id> [--chaos <profile>] [--seed 42] \\
        --history-start <iso> --parts-dir <lab disk path>

`ops=`, `lock_store=` and `clock=` are injectable so tests never need the live stack.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
for _path in (HERE, HERE.parent):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from chaos import lock  # noqa: E402
from lab_ops import LabOps, sha256_file  # noqa: E402

GRACE = timedelta(hours=1)  # D11: as_of = alert_at + grace
HISTORY = timedelta(days=31)  # D1: the guaranteed window reaches back at most 31 days
SETTLE_S = 60.0  # r6: documents still in the ingest pipeline land before captured_at


class WallClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def sleep_until(self, moment: datetime) -> None:
        while (left := (moment - self.now()).total_seconds()) > 0:
            time.sleep(min(left, 60.0))


def _utc(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _report(slug: str, window: list[str], fingerprint: dict, parts: dict) -> str:
    """O8: what the guaranteed window holds, per index, and what was stored."""
    per_index: dict[str, int] = {}
    for key, value in fingerprint.items():
        index = key.split("|", 1)[0]
        per_index[index] = per_index.get(index, 0) + int(value[0])
    lines = [f"captured {slug}: window {window[0]} .. {window[1]}"]
    lines += [f"  {count:>10}  {index}" for index, count in sorted(per_index.items())]
    if not per_index:
        lines.append("  (no documents in the window)")
    lines.append(f"parts ({len(parts)}):")
    lines += [f"  {name}" for name in sorted(parts)]
    return "\n".join(lines)


def capture(case_dir: Path, *, scenario: str, rule: str, chaos: str, ops: Any, lock_store: Any,
            parts_dir: Path, clock: Any, history_start: Any, seed: int = 42,
            settle_s: float = SETTLE_S) -> dict:
    """Capture `case_dir`'s freeze; returns {"freeze": ..., "report": ...}."""
    case_dir, parts_dir = Path(case_dir), Path(parts_dir)
    slug = case_dir.name
    # The Elasticsearch clock and fingerprint are the production ones unless `ops` brings its own.
    missing = [m for m in ("es_now", "refresh", "fingerprint") if getattr(ops, m, None) is None]
    production = LabOps() if missing else None
    es_now, refresh, fingerprint_of = (getattr(ops, m, None) or getattr(production, m)
                                       for m in ("es_now", "refresh", "fingerprint"))

    token = lock.take(lock_store, lock.CAPTURE)
    keep_lock = False
    ledger_ref = None
    revert_tried = reverted = False
    staging: Path | None = None
    try:
        fired = ops.fire(scenario, chaos, seed, token)
        ledger_ref = fired.get("ledger_ref")
        # The case's alert is its rule's, never another alert on the same host.
        alert = ops.wait_alert({**fired, "rule_id": rule})
        alert_at = _utc(alert["@timestamp"])
        as_of = alert_at + GRACE
        clock.sleep_until(as_of)

        # The fault is still live: snapshot first, then revert (P3/O7). proc-tree and stub dumps
        # first; host commits pause each host, so they and the volume copies come after.
        parts_dir.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=f".{slug}.", dir=parts_dir))
        names = []
        names += ops.proc_tree(staging)
        names += ops.stub_dumps(staging)
        names += ops.commit_hosts(staging, as_of)
        names += ops.copy_volumes(staging)

        if ledger_ref is not None:
            revert_tried = True
            ops.revert(ledger_ref)
            reverted = True

        clock.sleep(settle_s)
        captured_at = _utc(es_now())
        refresh()
        lower = max(_utc(history_start), alert_at - HISTORY)
        window = [_iso(lower), _iso(as_of)]
        fingerprint = fingerprint_of([lower, as_of], as_of, captured_at)

        parts = {name: "sha256:" + sha256_file(staging / name) for name in names}
        freeze = {
            "alert_at": _iso(alert_at),
            "as_of": _iso(as_of),
            "window": window,
            "captured_at": _iso(captured_at),
            "fingerprint": {k: [int(x) for x in v] for k, v in sorted(fingerprint.items())},
            "parts": parts,
            "chaos": None if not chaos or chaos == "none" else
            {"profile": chaos, "seed": seed, "ledger_ref": ledger_ref},
            "confirmed": {},
        }
        _commit(case_dir, parts_dir / slug, staging, freeze, alert)
        staging = None
    except BaseException:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        if ledger_ref is not None and not revert_tried:
            try:
                ops.revert(ledger_ref)
            except Exception as revert_exc:
                keep_lock = True
                print(f"revert of {ledger_ref} failed ({revert_exc}); the capture lock stays "
                      "held: revert the fault, then clear the lock", file=sys.stderr)
        elif revert_tried and not reverted:
            keep_lock = True
            print(f"revert of {ledger_ref} failed; the capture lock stays held: revert the "
                  "fault, then clear the lock", file=sys.stderr)
        raise
    finally:
        if not keep_lock:
            lock.release(lock_store, lock.CAPTURE, token)

    report = _report(slug, window, freeze["fingerprint"], parts)
    print(report)
    return {"freeze": freeze, "report": report}


def _commit(case_dir: Path, mine: Path, staging: Path, freeze: dict, alert: dict) -> None:
    """Swap the staged parts in and write freeze.yaml (and alert.json when the case has none).
    The freeze file is written to a temporary name first and renamed last."""
    tmp = case_dir / ".freeze.yaml.tmp"
    tmp.write_text(yaml.safe_dump(freeze, sort_keys=False))
    old = None
    swapped = False
    try:
        if mine.exists():
            old = mine.with_name(f".{mine.name}.old")
            shutil.rmtree(old, ignore_errors=True)
            mine.rename(old)
        staging.rename(mine)
        swapped = True
        alert_file = case_dir / "alert.json"
        if not alert_file.exists():
            alert_file.write_text(json.dumps(alert, indent=2) + "\n")
        os.replace(tmp, case_dir / "freeze.yaml")
    except BaseException:
        # The earlier parts go back under the earlier freeze: never new parts under an old one.
        if swapped:
            shutil.rmtree(mine, ignore_errors=True)
        if old is not None:
            old.rename(mine)
        raise
    finally:
        tmp.unlink(missing_ok=True)
    if old is not None:
        shutil.rmtree(old, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture a held-out case's freeze")
    parser.add_argument("case_dir", type=Path, help="the held-out case dir (its name is the slug)")
    parser.add_argument("--scenario", required=True, help="attack scenario id (runner.py list)")
    parser.add_argument("--rule", required=True,
                        help="the detection rule_id whose alert is the case's (detection-rules/)")
    parser.add_argument("--chaos", default="none", help="chaos profile held until as_of")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--history-start", default=os.environ.get("V2_HISTORY_START"),
                        help="the cluster's one history start (D1); default $V2_HISTORY_START")
    parser.add_argument("--parts-dir", type=Path, default=os.environ.get("V2_FROZEN_PARTS_DIR"),
                        help="the lab disk path parts live under (D8); default $V2_FROZEN_PARTS_DIR")
    parser.add_argument("--settle-s", type=float, default=SETTLE_S)
    args = parser.parse_args(argv)
    if not args.history_start or not args.parts_dir:
        parser.error("--history-start and --parts-dir are required (or their V2_ settings)")
    try:
        capture(args.case_dir, scenario=args.scenario, rule=args.rule, chaos=args.chaos,
                ops=LabOps(),
                lock_store=lock.DockerLockStore(), parts_dir=args.parts_dir, clock=WallClock(),
                history_start=args.history_start, seed=args.seed, settle_s=args.settle_s)
    except lock.LockError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
