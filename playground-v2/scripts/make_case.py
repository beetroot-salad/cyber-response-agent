#!/usr/bin/env python3
"""List a freeze's candidate alerts and write a case from the readied variant (#1347 O13, A1).

    make_case.py list <freeze-dir>
    make_case.py write <case-dir> --freeze <freeze-dir> --alert <kibana.alert.uuid> \\
        [--profile P --seed N --span-start ISO]

`write` writes a case only for a candidate of `list`. It takes the frozen-engine lock, readies the
variant with a whole restore (never trusting a copy-state marker, D23), runs the chaos guard
against the rules as of T, and writes `alert.json` and `case.yaml` (`confirmed` empty). The index
patterns are the freeze's, which must be the lab tenant's current ones under
`$V2_FROZEN_TENANT_DIR` (D24). The lock stays held for labelling: run
`launch_frozen.py --reference --lock-token <token>` against the case, label it, fill `confirmed`,
then release. Any refusal or failure leaves the case
directory as it was and frees the lock.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
for _path in (HERE, HERE.parent, REPO):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import frozen_copy  # noqa: E402
from chaos import lock  # noqa: E402
from chaos.guard import check_mutations  # noqa: E402
from chaos.mutations import resolve_mutations  # noqa: E402
from chaos.profiles import load_profile  # noqa: E402

MAX_AGE = timedelta(hours=6)   # D17: the one owner of the candidate window

PLAYGROUND = HERE.parent


class CaseRefused(RuntimeError):
    """The case cannot be written: its alert is not in the variant's copy, or alert.json is not it."""


def _freeze_of(freeze_dir: Path) -> dict:
    path = Path(freeze_dir) / "freeze.yaml"
    freeze = yaml.safe_load(path.read_text()) if path.is_file() else None
    frozen_copy.check_freeze(freeze, Path(freeze_dir).name)
    return freeze


def candidates(freeze_dir: Path, *, ops: Any, max_age: timedelta = MAX_AGE) -> list[str]:
    """`kibana.alert.uuid` of each alert in the freeze's snapshot stamped in [T - max_age, T], with
    no live run, no ticket reference and the default (`open`) workflow status; oldest first.
    The one owner of eligibility: `write_case` writes only what this lists."""
    T = frozen_copy.utc(_freeze_of(freeze_dir)["T"])
    skip = set(ops.live_run_alerts()) | set(ops.ticketed_alerts())
    found = []
    for alert in ops.snapshot_alerts(freeze_dir):
        uuid = frozen_copy.alert_uuid(alert)
        stamped = frozen_copy.dug(alert, "@timestamp")
        if (not uuid or uuid in skip or not stamped
                or frozen_copy.dug(alert, "kibana.alert.workflow_status") != "open"):
            continue
        at = frozen_copy.utc(stamped)
        if T - max_age <= at <= T:
            found.append((at, uuid))
    return [uuid for _at, uuid in sorted(found)]


class Held:
    """The frozen-engine lock make-a-case keeps through labelling. A context manager."""

    def __init__(self, lock_store: Any, token: str) -> None:
        self._store, self.token, self._open = lock_store, token, True

    def release(self) -> None:
        if self._open:
            self._open = False
            lock.release(self._store, lock.FROZEN_ENGINE, self.token)

    def __enter__(self) -> Held:
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()


def _overlay_of(overlay: dict | None, T: datetime, *, profiles_dir: Path, inventory: dict) -> dict | None:
    """`{mutations, span_start}` as case.yaml records it: the resolved mutations, not the profile."""
    if overlay is None:
        return None
    span = frozen_copy.utc(overlay["span_start"])
    if span > T:
        raise CaseRefused(f"the overlay's span starts at {frozen_copy.stamp(span)}, after T")
    profile = load_profile(overlay["profile"], profiles_dir=Path(profiles_dir))
    mutations = resolve_mutations(profile, seed=int(overlay["seed"]), inventory=inventory)
    return {"mutations": mutations, "span_start": frozen_copy.stamp(span)}


def _alert_of_copy(es: Any, patterns: list[str], uuid: str, case_dir: Path) -> dict:
    alert = frozen_copy.find_alert(es, patterns, uuid)
    if alert is None:
        raise CaseRefused(f"alert {uuid} is not in the variant's copy (never there, or stamped after T)")
    placed = case_dir / "alert.json"
    if placed.exists() and json.loads(placed.read_text()) != alert:
        raise CaseRefused(f"{placed} is not the copy's alert document for {uuid}")
    return alert


def _record(*, freeze: dict, freeze_id: str, overlay: dict | None, alert: dict, copy: frozen_copy.Copy,
            es: Any, ops: Any) -> dict:
    observed = frozen_copy.observed_counts(es, list(copy.counts))
    if observed != copy.counts:
        wrong = {n: (observed[n], copy.counts[n]) for n in copy.counts if observed[n] != copy.counts[n]}
        raise frozen_copy.CopyFault(f"the restore returned other documents than the freeze counted "
                                    f"(observed, derived): {wrong}")
    T = frozen_copy.utc(freeze["T"])
    return {"freeze": freeze_id, "alert": frozen_copy.digest_of(alert),
            "age": int((T - frozen_copy.utc(frozen_copy.dug(alert, "@timestamp"))).total_seconds()),
            "overlay": overlay, "counts": copy.counts, "content": ops.content_digest(copy.touched),
            "confirmed": None}


def _remember(case_dir: Path) -> Any:
    """What `case_dir` holds now; the returned function puts it back (the two files, and any
    directory this call is about to create). Something that is not a plain file is left alone."""
    missing = []
    node = case_dir
    while not node.exists():
        missing.append(node)
        node = node.parent
    prior = {name: (case_dir / name).read_bytes() if (case_dir / name).is_file() else None
             for name in ("alert.json", "case.yaml") if not (case_dir / name).exists() or (case_dir / name).is_file()}

    def restore() -> None:
        for name, data in prior.items():
            if data is None:
                (case_dir / name).unlink(missing_ok=True)
            else:
                (case_dir / name).write_bytes(data)
        for directory in missing:
            try:
                directory.rmdir()
            except OSError:
                pass
    return restore


def _write(case_dir: Path, alert: dict, case: dict) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "alert.json").write_text(json.dumps(alert, indent=2) + "\n")
    (case_dir / "case.yaml").write_text(yaml.safe_dump(case, sort_keys=False))


def write_case(case_dir: Path, *, freeze_dir: Path, alert_uuid: str, overlay: dict | None,
               tenant_settings: Path, parts_dir: Path, lock_store: Any, es: Any, ops: Any, clock: Any,
               profiles_dir: Path, inventory: dict, location: str = frozen_copy.REPO_LOCATION) -> Held:
    """Ready the variant, check the alert and the guard, write the case; returns the held lock.
    `tenant_settings` is the lab tenant's `settings/` directory; the copy uses the freeze's patterns,
    which must be the tenant's current ones (D24)."""
    case_dir, freeze_dir = Path(case_dir), Path(freeze_dir)
    freeze, freeze_id = _freeze_of(freeze_dir), freeze_dir.name
    frozen_copy.check_patterns(freeze, tenant_settings)
    frozen_copy.check_parts(freeze, Path(parts_dir) / freeze_id)
    if alert_uuid not in candidates(freeze_dir, ops=ops):
        raise CaseRefused(f"alert {alert_uuid} is not a candidate of {freeze_id} (see `list`): outside "
                          "[T - max age, T], or it has a live run, a ticket or a changed workflow status")
    recorded = _overlay_of(overlay, frozen_copy.utc(freeze["T"]), profiles_dir=profiles_dir,
                           inventory=inventory)
    if recorded:   # the guard, against the rules as of T, before the copy is touched
        rules = Path(ops.freeze_rules(freeze_dir))
        try:
            check_mutations(recorded["mutations"], rules_dir=rules)
        finally:   # needed only by the guard: removed on every exit, a refusal included
            shutil.rmtree(rules, ignore_errors=True)
    token = lock.take(lock_store, lock.FROZEN_ENGINE)
    restore = None
    try:
        copy = frozen_copy.ready(es, ops=ops, clock=clock, freeze=freeze, freeze_id=freeze_id,
                                 overlay=recorded, whole=True, location=location)
        if dangling := frozen_copy.unverifiable_ancestry(es, freeze, recorded):
            raise CaseRefused(f"the schema-drift's span holds alerts built from events of {dangling}, which "
                              f"the copy does not hold: their derived alerts cannot be found (pick a later span)")
        ops.load_stubs(Path(parts_dir) / freeze_id, frozen_copy.stamp(freeze["T"]),
                       (recorded or {}).get("mutations") or None)
        alert = _alert_of_copy(es, list(freeze["patterns"]), alert_uuid, case_dir)
        case = _record(freeze=freeze, freeze_id=freeze_id, overlay=recorded, alert=alert, copy=copy,
                       es=es, ops=ops)
        restore = _remember(case_dir)
        _write(case_dir, alert, case)
        ops.teardown()   # the stubs stop; the copy stays for the reference run
    except BaseException:
        try:
            for undo in (restore, ops.teardown):
                try:
                    if undo is not None:
                        undo()
                except Exception as exc:  # noqa: BLE001 - the first failure is the one to report
                    print(f"cleanup after a failed case also failed: {exc}", file=sys.stderr)
        finally:
            lock.release(lock_store, lock.FROZEN_ENGINE, token)
        raise
    return Held(lock_store, token)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="List candidate alerts / write a held-out case")
    sub = parser.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list")
    ls.add_argument("freeze_dir", type=Path)
    wr = sub.add_parser("write")
    wr.add_argument("case_dir", type=Path)
    wr.add_argument("--freeze", type=Path, required=True, dest="freeze_dir")
    wr.add_argument("--alert", required=True)
    wr.add_argument("--profile")
    wr.add_argument("--seed", type=int, default=42)
    wr.add_argument("--span-start")
    wr.add_argument("--parts-dir", type=Path, default=os.environ.get("V2_FROZEN_PARTS_DIR"))
    args = parser.parse_args(argv)
    from lab_ops import LabOps, NotConfigured
    ops = LabOps.from_environment()
    if args.cmd == "list":
        try:
            print("\n".join(candidates(args.freeze_dir, ops=ops)))
        except NotConfigured as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 4
        return 0
    if not args.parts_dir or bool(args.profile) != bool(args.span_start):
        parser.error("--parts-dir (or $V2_FROZEN_PARTS_DIR) is required; --profile needs --span-start")
    try:
        held = write_case(
            args.case_dir, freeze_dir=args.freeze_dir, alert_uuid=args.alert,
            overlay={"profile": args.profile, "seed": args.seed, "span_start": args.span_start}
            if args.profile else None,
            tenant_settings=frozen_copy.tenant_settings_dir(), parts_dir=args.parts_dir,
            lock_store=lock.DockerLockStore(), es=ops.frozen_es(), ops=ops, clock=frozen_copy.WallClock(),
            profiles_dir=PLAYGROUND / "chaos" / "profiles",
            inventory=yaml.safe_load((PLAYGROUND / "hosts" / "inventory.yaml").read_text()))
    except (CaseRefused, frozen_copy.CopyRefused, lock.LockError, NotConfigured) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 4
    print(f"case written to {args.case_dir}; the frozen-engine lock is held, token {held.token}")
    print(f"label it: launch_frozen.py {args.case_dir} --reference --lock-token {held.token} ...")
    print("then fill `confirmed` in case.yaml and release: python3 chaos/lock.py clear frozen-engine")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
