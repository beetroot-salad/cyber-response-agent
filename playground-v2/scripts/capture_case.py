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
import hashlib
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
from lab_ops import LabOps, sha256_file, stamp, utc  # noqa: E402

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
    # The activated fault's ledger ref (recorded in the freeze), and the same ref while the fault
    # may still be live. Activation comes first and alone, so capture holds the ref before
    # anything else can fail, and is the only place the fault is undone (r6.2).
    ledger_ref: str | None = None
    live: str | None = None
    staging: Path | None = None
    try:
        if chaos and chaos != "none":
            ledger_ref = live = ops.activate(chaos, seed, token)
        fired = ops.fire(scenario, seed, token)
        # The case's alert is its rule's, never another alert on the same host.
        alert = ops.wait_alert({**fired, "rule_id": rule})
        alert_at = utc(alert["@timestamp"])
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

        if live is not None:
            try:
                ops.revert(live)
            except BaseException:
                keep_lock = True
                raise
            live = None

        clock.sleep(settle_s)
        captured_at = utc(es_now())
        refresh()
        lower = max(utc(history_start), alert_at - HISTORY)
        window = [stamp(lower), stamp(as_of)]
        fingerprint = fingerprint_of([lower, as_of], as_of, captured_at)

        parts = {name: "sha256:" + sha256_file(staging / name) for name in names}
        # The case's alert, bound into the freeze by its bytes (r6.2): every capture writes it,
        # so a re-captured case never keeps an earlier alert beside a freeze built around another.
        alert_bytes = (json.dumps(alert, indent=2) + "\n").encode("utf-8")
        freeze = {
            "alert_at": stamp(alert_at),
            "alert": "sha256:" + hashlib.sha256(alert_bytes).hexdigest(),
            "as_of": stamp(as_of),
            "window": window,
            "captured_at": stamp(captured_at),
            "fingerprint": {k: [int(x) for x in v] for k, v in sorted(fingerprint.items())},
            "parts": parts,
            "chaos": None if not chaos or chaos == "none" else
            {"profile": chaos, "seed": seed, "ledger_ref": ledger_ref},
            "confirmed": {},
        }
        _commit(case_dir, parts_dir / slug, staging, freeze, alert_bytes)
        staging = None
    except BaseException:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        if live is not None and not keep_lock:
            try:
                ops.revert(live)
            except BaseException:
                keep_lock = True
        if keep_lock:
            print(f"revert of {live} failed; the capture lock stays held: revert the fault, "
                  "then clear the lock", file=sys.stderr)
        raise
    finally:
        if not keep_lock:
            lock.release(lock_store, lock.CAPTURE, token)

    report = _report(slug, window, freeze["fingerprint"], parts)
    print(report)
    return {"freeze": freeze, "report": report}


def _commit(case_dir: Path, mine: Path, staging: Path, freeze: dict, alert: bytes) -> None:
    """Swap the staged parts in, then write alert.json and freeze.yaml, the freeze last. Both
    files are written to temporary names first; on a failure the earlier parts and the earlier
    alert go back, so a case is never left with new parts or a new alert under an old freeze."""
    tmp = case_dir / ".freeze.yaml.tmp"
    alert_tmp = case_dir / ".alert.json.tmp"
    alert_file = case_dir / "alert.json"
    tmp.write_text(yaml.safe_dump(freeze, sort_keys=False))
    alert_tmp.write_bytes(alert)
    earlier_alert = alert_file.read_bytes() if alert_file.is_file() else None
    old = None
    swapped = alert_swapped = False
    try:
        if mine.exists():
            old = mine.with_name(f".{mine.name}.old")
            shutil.rmtree(old, ignore_errors=True)
            mine.rename(old)
        staging.rename(mine)
        swapped = True
        os.replace(alert_tmp, alert_file)
        alert_swapped = True
        os.replace(tmp, case_dir / "freeze.yaml")
    except BaseException:
        # The earlier parts and alert go back under the earlier freeze.
        if alert_swapped:
            if earlier_alert is None:
                alert_file.unlink(missing_ok=True)
            else:
                alert_file.write_bytes(earlier_alert)
        if swapped:
            shutil.rmtree(mine, ignore_errors=True)
        if old is not None:
            old.rename(mine)
        raise
    finally:
        tmp.unlink(missing_ok=True)
        alert_tmp.unlink(missing_ok=True)
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
