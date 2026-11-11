#!/usr/bin/env python3
"""Launch one held-out case on its variant's frozen copy and write the run's index row (#1347).

Every scored held-out run is started here, under the frozen engine's lab-server lock:

    verify case, freeze and parts (refuse: no cluster request, no row) -> take the lock ->
    ready the variant (a fresh node, restore + overlays; or trust a clean marker) -> load the
    stubs pinned at T -> serve the freeze's hosts (replicas + endpoint-query, #1391) -> wait
    for health -> create the read-only user -> compare counts, content digest and alert with case.yaml -> start the frozen proxy -> rewrite the node's clock offset
    to T - now -> run the agent with `--as-of T` -> append the row -> tear down -> release the lock

The node's clock (D15 revised) reads T whenever the node starts, and the offset rewrite is the
last lab step before the agent runs, so the node's clock and the agent's `--as-of T` start
together. The node is never restarted for its clock.

A copy that cannot be made (restore, overlay, marker, services, health) is a launch failure: it
raises, writes no row and leaves no clean marker. A copy that differs from what the case recorded
is a `stale` row, and the marker is marked dirty so the next launch restores whole (D23). The
index patterns are the freeze's; a freeze whose patterns are not the lab tenant's current ones
(`patterns`) is refused before anything runs (D24).

A run that dies before printing `run_id=` gets no row. `--reference` serves the
copy the same way but appends no row and prints the run id, for labelling (O8); it works before
`confirmed` is filled. `lock_token` joins a lock make-a-case holds and leaves it held.

    defender/.venv/bin/python playground-v2/scripts/launch_frozen.py \\
        evaluations/fixtures/held_out/<slug> --tenant "$TENANT_ID" --index F \\
        --parts-dir <lab disk path> [--knowledge-commit K] [--reference] [--lock-token T]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
for _path in (HERE, HERE.parent, REPO):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import frozen_copy  # noqa: E402
from chaos import lock  # noqa: E402
from defender._io import append_jsonl  # noqa: E402
from evaluations import held_out  # noqa: E402
from evaluations.held_out import binding  # noqa: E402

CASE_KEYS = ("freeze", "alert", "counts", "content")


class LaunchRefused(RuntimeError):
    """The case cannot be served: malformed, unconfirmed, or its freeze/parts/snapshot are not
    what it names. Nothing ran and no row was written."""


class RunDied(RuntimeError):
    """The agent ended without announcing a run id; there is nothing to bind a row to."""


class TeardownFailed(RuntimeError):
    """The run finished and its row (if any) is written, but tearing the copy down failed."""


def _load_yaml(path: Path, what: str) -> Any:
    from defender._io import read_text_utf8  # the scorer's own loader, so both read one document
    from defender._yaml import safe_load
    try:
        return safe_load(read_text_utf8(path))
    except Exception as exc:  # noqa: BLE001 - any unreadable file is a refusal
        raise LaunchRefused(f"{what} ({path}) is unreadable: {exc}") from exc


def load_case(case_dir: Path) -> dict:
    path = case_dir / "case.yaml"
    if not path.is_file():
        raise LaunchRefused(f"{case_dir.name} has no case.yaml: a fixture without one is not a case")
    case = _load_yaml(path, "case.yaml")
    missing = [k for k in CASE_KEYS if not isinstance(case, dict) or case.get(k) in (None, "", {})]
    if missing:
        raise LaunchRefused(f"case.yaml of {case_dir.name} lacks {', '.join(missing)}")
    if not isinstance(case["counts"], dict) or not all(isinstance(v, int) for v in case["counts"].values()):
        raise LaunchRefused("case.yaml: counts must map index names to integers")
    if not all(isinstance(case[k], str) for k in ("freeze", "alert", "content")):
        raise LaunchRefused("case.yaml: freeze, alert and content must be text")
    if case.get("overlay") is not None and not isinstance(case["overlay"], dict):
        raise LaunchRefused("case.yaml: overlay must be none or {mutations, span_start}")
    return case


def alert_uuid_of(alert_file: Path) -> str:
    try:
        doc = json.loads(alert_file.read_text())
    except (OSError, ValueError) as exc:
        raise LaunchRefused(f"{alert_file} is not a readable alert document: {exc}") from exc
    uuid = frozen_copy.alert_uuid(doc)
    if uuid is None:
        raise LaunchRefused(f"{alert_file} carries no kibana.alert.uuid")
    return uuid


def verify(case_dir: Path, freezes_dir: Path, parts_dir: Path, reference: bool) -> tuple[dict, dict, dict, str]:
    """Everything that needs no cluster: `(case, freeze, row binding, alert uuid)` or a refusal."""
    case = load_case(case_dir)
    if not reference and not case.get("confirmed"):
        raise LaunchRefused(f"{case_dir.name}: case.yaml is not confirmed; label it against a "
                            "--reference run first")
    freeze_id = case["freeze"]
    if Path(freeze_id).name != freeze_id:
        raise LaunchRefused(f"{freeze_id!r} is not a freeze id")
    freeze_file = freezes_dir / freeze_id / "freeze.yaml"
    if not freeze_file.is_file():
        raise LaunchRefused(f"{case_dir.name} names freeze {freeze_id}, which has no freeze.yaml")
    freeze = _load_yaml(freeze_file, "freeze.yaml")
    try:
        frozen_copy.check_freeze(freeze, freeze_id)
        frozen_copy.check_parts(freeze, parts_dir / freeze_id)
        bound = binding(freeze, case)
    except (frozen_copy.CopyRefused, TypeError, ValueError) as exc:
        raise LaunchRefused(str(exc)) from exc
    return case, freeze, {"binding": bound}, alert_uuid_of(case_dir / "alert.json")


def _stale(case: dict, observed: dict[str, int], content: str, alert: dict | None,
           alert_file_digest: str) -> list[str]:
    """What differs between the copy and case.yaml, as reasons."""
    reasons = []
    recorded = case["counts"]
    diff = [f"{n} has {observed.get(n)} documents, case recorded {recorded.get(n)}"
            for n in sorted(set(recorded) | set(observed)) if observed.get(n) != recorded.get(n)]
    if diff:
        reasons.append("counts differ: " + "; ".join(diff))
    if content != case["content"]:
        reasons.append("content digest differs from the case's")
    copy_alert = None if alert is None else held_out.digest(alert)
    if copy_alert != case["alert"] or alert_file_digest != case["alert"]:
        reasons.append("alert differs: the copy's alert, alert.json and case.yaml do not agree")
    return reasons


def _run_id(stdout: str) -> str | None:
    first = stdout.splitlines()[0] if stdout else ""
    if not first.startswith("run_id="):
        return None
    return first.removeprefix("run_id=").strip() or None


def _append_row(index: Path, row: dict) -> None:
    """One run row, through the product's JSONL appender. A torn last line (a write cut short)
    is ended first, so the new row is a line of its own and the scorer skips only the torn one."""
    try:
        with open(index, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            torn = fh.tell() > 0 and (fh.seek(-1, os.SEEK_END), fh.read(1))[1] != b"\n"
    except FileNotFoundError:
        torn = False
    if torn:
        with open(index, "ab") as fh:
            fh.write(b"\n")
    append_jsonl(index, [row])


def _default_run_fn(argv: list[str], env: dict) -> tuple[int, str, str]:
    proc = subprocess.run(argv, env=env, stdout=subprocess.PIPE, text=True)
    sys.stdout.write(proc.stdout)
    return proc.returncode, proc.stdout, ""


def _agent_python() -> str:
    venv = REPO / "defender" / ".venv" / "bin" / "python"
    return str(venv) if venv.exists() else sys.executable


def _serve_copy(es: Any, ops: Any, clock: Any, *, case: dict, freeze: dict, freeze_id: str,
                parts_dir: Path, alert_file: Path, location: str) -> list[str]:
    """Ready the copy, bring its services up and compare it with the case; returns the stale
    reasons. A stale copy is marked dirty so the next launch restores it whole."""
    overlay, patterns = case.get("overlay"), list(freeze["patterns"])
    T = frozen_copy.stamp(freeze["T"])
    copy = frozen_copy.ready(es, ops=ops, clock=clock, freeze=freeze, freeze_id=freeze_id,
                      overlay=overlay, location=location)
    ops.load_stubs(parts_dir / freeze_id, T, (overlay or {}).get("mutations") or None)
    ops.serve_hosts(parts_dir / freeze_id, freeze)   # host-state from the freeze's hosts (#1391 r6 O9)
    frozen_copy.wait_for_cluster(es, clock, "the copy")
    ops.create_readonly_user(ops.current_password())
    observed = frozen_copy.observed_counts(es, list(freeze["elastic"]["indices"]))
    uuid = alert_uuid_of(alert_file)
    alert = frozen_copy.find_alert(es, patterns, uuid)
    file_digest = held_out.digest(json.loads(alert_file.read_text()))
    reasons = _stale(case, observed, ops.content_digest(copy.touched), alert, file_digest)
    if reasons:
        frozen_copy.mark_dirty(ops, freeze_id, overlay)
    return reasons


def _quiet_teardown(ops: Any, why: str) -> None:
    try:
        ops.teardown()
    except Exception as exc:  # noqa: BLE001 - the first failure is the one to report
        print(f"teardown after {why} also failed: {exc}", file=sys.stderr)


def launch(case_dir: Path, *, freezes_dir: Path, tenant_settings: Path, index: Path, parts_dir: Path,
           lock_store: Any, es: Any, ops: Any, run_fn: Any = _default_run_fn, clock: Any = None,
           env: dict | None = None, tenant: str, knowledge: str | None = None,
           reference: bool = False, lock_token: str | None = None,
           location: str = frozen_copy.REPO_LOCATION) -> str:
    """Serve one frozen run of `case_dir`; returns its run id. `tenant_settings` is the lab tenant's
    `settings/` directory: the copy is made with the freeze's patterns, which must be the tenant's
    current ones (D24)."""
    case_dir, parts_dir, index = Path(case_dir), Path(parts_dir), Path(index)
    clock = clock if clock is not None else frozen_copy.WallClock()
    case, freeze, bound, _uuid = verify(case_dir, Path(freezes_dir), parts_dir, reference)
    try:
        frozen_copy.check_patterns(freeze, tenant_settings)
    except frozen_copy.CopyRefused as exc:
        raise LaunchRefused(str(exc)) from exc
    slug, alert_file = case_dir.name, case_dir / "alert.json"
    token = lock_token
    if token is None:
        token = lock.take(lock_store, lock.FROZEN_ENGINE)
    else:
        # Joining needs a held lock whose holder is `token`; `lock.require` alone passes a free one.
        if lock_store.read(lock.FROZEN_ENGINE) is None:
            raise LaunchRefused("lock_token was passed, but the frozen-engine lock is not held")
        try:
            lock.require(lock_store, lock.FROZEN_ENGINE, token)
        except (lock.Held, lock.WrongToken) as exc:
            raise LaunchRefused(f"lock_token does not name the holder of the frozen-engine lock: {exc}") from exc
    try:
        try:
            reasons = _serve_copy(es, ops, clock, case=case, freeze=freeze, freeze_id=case["freeze"],
                                  parts_dir=parts_dir, alert_file=alert_file, location=location)
            proxy_url = ops.start_proxy()
            # The last lab step: the node's clock is rewritten from the VPS's clock at instant W,
            # and the agent's run clock is anchored at the same W (r6.4.6), so both read T + (now - W).
            anchor = ops.set_clock(freeze["T"])
            argv = [_agent_python(), str(REPO / "defender" / "run.py"), str(alert_file),
                    "--tenant", tenant, "--no-learn", "--as-of", frozen_copy.stamp(freeze["T"]),
                    "--as-of-anchor", frozen_copy.stamp(anchor)]
            if knowledge:
                argv += ["--knowledge-commit", knowledge]
            rc, stdout, _ = run_fn(argv, {**(os.environ if env is None else env),
                                          "DEFENDER_CREDENTIAL_PROXY_URL": proxy_url})
            run_id = _run_id(stdout)
            if run_id is None:
                raise RunDied(f"{slug}: the agent exited rc={rc} without announcing a run id; "
                              "no row written, re-launch")
            verified_at = frozen_copy.stamp(clock.now())
        except BaseException:
            _quiet_teardown(ops, "a failed launch")
            raise
        verdict, reason = ("stale", "; ".join(reasons)) if reasons else ("valid", "")
        try:
            if reference:
                print(f"run_id={run_id}")
                print(f"reference run of {slug}: verdict {verdict}" + (f" ({reason})" if reason else ""))
            else:
                _append_row(index, {"slug": slug, "run_id": run_id, "binding": bound["binding"],
                                    "verdict": verdict, "reason": reason, "verified_at": verified_at,
                                    "knowledge": knowledge})
                print(f"{slug}: run {run_id} verdict {verdict}" + (f" ({reason})" if reason else ""))
        except BaseException:
            _quiet_teardown(ops, "a failed row write")
            raise
        try:
            ops.teardown()
        except Exception as exc:
            done = "finished (reference, no row)" if reference else "recorded in the index"
            raise TeardownFailed(f"{slug}: run {run_id} {done}; tearing the copy down then failed "
                                 f"({exc}): stop the frozen services before the next launch") from exc
        return run_id
    finally:
        if lock_token is None:
            lock.release(lock_store, lock.FROZEN_ENGINE, token)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Launch a held-out case on its frozen copy")
    parser.add_argument("case_dir", type=Path, help="the held-out case dir (alert.json, case.yaml)")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--index", type=Path, help="the held-out index (JSON Lines) to append to")
    parser.add_argument("--freezes-dir", type=Path, default=None,
                        help="default: <case dir>/../freezes")
    parser.add_argument("--parts-dir", type=Path, default=os.environ.get("V2_FROZEN_PARTS_DIR"),
                        help="the lab disk path parts live under (D8); default $V2_FROZEN_PARTS_DIR")
    parser.add_argument("--knowledge-commit", default=None, metavar="SHA")
    parser.add_argument("--reference", action="store_true",
                        help="a labelling run: serve the copy, write no row, print the run id")
    parser.add_argument("--lock-token", default=None,
                        help="the token of the frozen-engine lock make-a-case holds")
    args = parser.parse_args(argv)
    if not args.parts_dir or (not args.reference and not args.index):
        parser.error("--parts-dir (or $V2_FROZEN_PARTS_DIR) and, unless --reference, --index are required")
    from lab_ops import LabOps
    ops = LabOps.from_environment()
    try:
        launch(args.case_dir, freezes_dir=args.freezes_dir or args.case_dir.resolve().parent / "freezes",
               tenant_settings=frozen_copy.tenant_settings_dir(), index=args.index or Path(os.devnull),
               parts_dir=args.parts_dir, lock_store=lock.DockerLockStore(), es=ops.frozen_es(), ops=ops,
               tenant=args.tenant, knowledge=args.knowledge_commit, reference=args.reference,
               lock_token=args.lock_token)
    except (lock.LockError, LaunchRefused, frozen_copy.CopyRefused, RunDied) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 4
    except TeardownFailed as exc:
        print(f"teardown failed: {exc}", file=sys.stderr)
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
