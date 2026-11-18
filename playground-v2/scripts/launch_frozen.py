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

Several case dirs of one variant are one batch: one lock, one copy, one teardown, the agents in waves
of `--parallel` (the clock rewritten before each wave). A run that dies before printing `run_id=` gets
no row; the batch's other runs keep theirs. `--reference` serves the
copy the same way but appends no row and prints the run id, for labelling (O8); it works before
`confirmed` is filled. `lock_token` joins a lock make-a-case holds and leaves it held.

    defender/.venv/bin/python playground-v2/scripts/launch_frozen.py \\
        evaluations/fixtures/held_out/<slug> [<slug> ...] --tenant "$TENANT_ID" --index F \\
        --parts-dir <lab disk path> [--knowledge-commit K] [--reference] [--lock-token T] [--parallel N]
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


def verify(case_dir: Path, freezes_dir: Path, reference: bool) -> tuple[dict, str]:
    """A case's own checks, which need no cluster and no freeze part: `(case, alert uuid)` or a refusal.
    The freeze it names is checked once per launch, by `check_freeze_of`."""
    case = load_case(case_dir)
    if not reference and not case.get("confirmed"):
        raise LaunchRefused(f"{case_dir.name}: case.yaml is not confirmed; label it against a "
                            "--reference run first")
    freeze_id = case["freeze"]
    if Path(freeze_id).name != freeze_id:
        raise LaunchRefused(f"{freeze_id!r} is not a freeze id")
    if not (freezes_dir / freeze_id / "freeze.yaml").is_file():
        raise LaunchRefused(f"{case_dir.name} names freeze {freeze_id}, which has no freeze.yaml")
    return case, alert_uuid_of(case_dir / "alert.json")


def check_freeze_of(freeze_id: str, freezes_dir: Path, parts_dir: Path,
                    trusted: dict | None = None) -> dict:
    """The batch's one freeze, loaded and checked: its record, every part against the digest freeze.yaml
    names (the slow step: a 17 GB freeze is read in full), and its host parts. Runs once per launch,
    after the one-variant rule, so neither a later case nor a refused batch hashes the parts again.
    `trusted` is what case writing recorded on the lock a labelling launch joins: the hashing is
    skipped only when the parts look exactly as they did then (`frozen_copy.parts_checked`)."""
    freeze = _load_yaml(freezes_dir / freeze_id / "freeze.yaml", "freeze.yaml")
    try:
        frozen_copy.check_freeze(freeze, freeze_id)
        if trusted is None or trusted != frozen_copy.parts_checked(freeze, freeze_id, parts_dir / freeze_id):
            frozen_copy.check_parts(freeze, parts_dir / freeze_id)
    except (frozen_copy.CopyRefused, TypeError, ValueError) as exc:
        raise LaunchRefused(str(exc)) from exc
    from lab_ops import LabOps, LabOpsError
    try:
        LabOps.check_host_parts(freeze)
    except LabOpsError as exc:
        raise LaunchRefused(str(exc)) from exc
    return freeze


def _bound(freeze: dict, case: dict) -> dict:
    try:
        return {"binding": binding(freeze, case)}
    except (TypeError, ValueError) as exc:
        raise LaunchRefused(str(exc)) from exc


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


def _serve_copy(es: Any, ops: Any, clock: Any, *, cases: list[dict], alert_files: list[Path], freeze: dict,
                freeze_id: str, parts_dir: Path, location: str) -> list[list[str]]:
    """Ready the copy, bring its services up and compare it with each case (one variant); returns each
    case's stale reasons. A stale copy is marked dirty so the next launch restores it whole."""
    overlay, patterns = cases[0].get("overlay"), list(freeze["patterns"])
    T = frozen_copy.stamp(freeze["T"])
    copy = frozen_copy.ready(es, ops=ops, clock=clock, freeze=freeze, freeze_id=freeze_id,
                      overlay=overlay, location=location)
    ops.load_stubs(parts_dir / freeze_id, T, (overlay or {}).get("mutations") or None)
    ops.serve_hosts(parts_dir / freeze_id, freeze)   # host-state from the freeze's hosts (#1391 r6 O9)
    frozen_copy.wait_for_cluster(es, clock, "the copy")
    ops.create_readonly_user(ops.current_password())
    observed = frozen_copy.observed_counts(es, list(freeze["elastic"]["indices"]))
    alerts = [(frozen_copy.find_alert(es, patterns, alert_uuid_of(f)), held_out.digest(json.loads(f.read_text())))
              for f in alert_files]
    content, read = frozen_copy.content_of(es, ops, copy, freeze_id=freeze_id, overlay=overlay)
    print(f"copy {'restored' if copy.restored else 'reused'}; content "
          f"{'read in full' if read else 'trusted from its record (writes blocked)'}", file=sys.stderr)
    reasons = [_stale(case, observed, content, alert, digest) for case, (alert, digest) in zip(cases, alerts)]
    if any(reasons):
        frozen_copy.mark_dirty(ops, freeze_id, overlay)
    return reasons


def _quiet_teardown(ops: Any, why: str) -> None:
    try:
        ops.teardown()
    except Exception as exc:  # noqa: BLE001 - the first failure is the one to report
        print(f"teardown after {why} also failed: {exc}", file=sys.stderr)


def _run_wave(run_fn: Any, jobs: list[tuple[list[str], dict]]) -> list[tuple[int, str]]:
    """Each job's `(rc, stdout)`, in order. One job runs here; several run at once, and all of them have
    ended before this returns (a failure of one is raised once every other has ended)."""
    if len(jobs) == 1:
        rc, stdout, _ = run_fn(*jobs[0])
        return [(rc, stdout)]
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = [pool.submit(run_fn, argv, env) for argv, env in jobs]
    return [(f.result()[0], f.result()[1]) for f in futures]


def launch(case_dir: Path, **kw: Any) -> str:
    """Serve one frozen run of `case_dir`; returns its run id. See `launch_batch`."""
    return launch_batch([case_dir], **kw)[0]


def launch_batch(case_dirs: list[Path], *, freezes_dir: Path, tenant_settings: Path, index: Path, parts_dir: Path,
                 lock_store: Any, es: Any, ops: Any, run_fn: Any = _default_run_fn, clock: Any = None,
                 env: dict | None = None, tenant: str, knowledge: str | None = None,
                 reference: bool = False, lock_token: str | None = None, parallel: int = 1,
                 location: str = frozen_copy.REPO_LOCATION) -> list[str]:
    """Serve one frozen run of each case in `case_dirs`, all of one variant, on one copy; returns their
    run ids in order. The agents run in waves of up to `parallel`: the node's clock is rewritten before
    each wave, and every agent of a wave starts from that one rewrite. A case whose agent dies gets no
    row; the others keep theirs, and `RunDied` names every one that died once the copy is torn down.
    `tenant_settings` is the lab tenant's `settings/` directory: the copy is made with the freeze's
    patterns, which must be the tenant's current ones (D24)."""
    dirs, parts_dir, index = [Path(d) for d in case_dirs], Path(parts_dir), Path(index)
    if not dirs:
        raise LaunchRefused("no case to launch")
    if parallel < 1:
        raise LaunchRefused("--parallel must be at least 1")
    if len({d.name for d in dirs}) != len(dirs):
        raise LaunchRefused("a batch names one case twice")
    clock = clock if clock is not None else frozen_copy.WallClock()
    checked = [verify(d, Path(freezes_dir), reference) for d in dirs]
    cases = [c[0] for c in checked]
    variants = {frozen_copy.variant_id(c["freeze"], c.get("overlay")) for c in cases}
    if len(variants) != 1:
        raise LaunchRefused("a batch is one variant (one freeze, one overlay); these cases name "
                            f"{len(variants)}: launch each variant on its own")
    # Only a labelling launch joining make-a-case's lock trusts its parts check; a scored launch hashes.
    note = lock.note_of(lock_store, lock.FROZEN_ENGINE, lock_token) if reference and lock_token else None
    freeze = check_freeze_of(cases[0]["freeze"], Path(freezes_dir), parts_dir,
                             trusted=(note or {}).get("parts_checked"))
    bindings = [_bound(freeze, c) for c in cases]
    try:
        frozen_copy.check_patterns(freeze, tenant_settings)
    except frozen_copy.CopyRefused as exc:
        raise LaunchRefused(str(exc)) from exc
    alert_files = [d / "alert.json" for d in dirs]
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
    run_ids: list[str] = []
    died: list[str] = []
    try:
        try:
            reasons = _serve_copy(es, ops, clock, cases=cases, alert_files=alert_files, freeze=freeze,
                                  freeze_id=cases[0]["freeze"], parts_dir=parts_dir, location=location)
            proxy_url = ops.start_proxy()
            agent_env = {**(os.environ if env is None else env), "DEFENDER_CREDENTIAL_PROXY_URL": proxy_url}
            for start in range(0, len(dirs), parallel):
                wave = list(range(start, min(start + parallel, len(dirs))))
                # The last lab step before a wave: the node's clock is rewritten from the VPS's clock at
                # instant W, and each agent's run clock is anchored at the same W (r6.4.6), so all read
                # T + (now - W).
                ops.check_reachable()        # no wave starts on a copy its agents cannot reach
                anchor = ops.set_clock(freeze["T"])
                jobs = []
                for i in wave:
                    argv = [_agent_python(), str(REPO / "defender" / "run.py"), str(alert_files[i]),
                            "--tenant", tenant, "--no-learn", "--as-of", frozen_copy.stamp(freeze["T"]),
                            "--as-of-anchor", frozen_copy.stamp(anchor)]
                    if knowledge:
                        argv += ["--knowledge-commit", knowledge]
                    jobs.append((argv, agent_env))
                for i, (rc, stdout) in zip(wave, _run_wave(run_fn, jobs)):
                    slug, run_id = dirs[i].name, _run_id(stdout)
                    if run_id is None:
                        died.append(f"{slug}: the agent exited rc={rc} without announcing a run id; "
                                    "no row written, re-launch")
                        continue
                    _report(slug, run_id, reasons[i], reference=reference, index=index,
                            binding=bindings[i]["binding"], verified_at=frozen_copy.stamp(clock.now()),
                            knowledge=knowledge)
                    run_ids.append(run_id)
        except BaseException:
            _quiet_teardown(ops, "a failed launch")
            raise
        if died:
            _quiet_teardown(ops, "a run that died")
            raise RunDied("; ".join(died))
        try:
            ops.teardown()
        except Exception as exc:
            done = "finished (reference, no row)" if reference else "recorded in the index"
            raise TeardownFailed(f"{', '.join(d.name for d in dirs)}: run {', '.join(run_ids)} {done}; tearing "
                                 f"the copy down then failed ({exc}): stop the frozen services before the next "
                                 "launch") from exc
        return run_ids
    finally:
        if lock_token is None:
            lock.release(lock_store, lock.FROZEN_ENGINE, token)


def _report(slug: str, run_id: str, reasons: list[str], *, reference: bool, index: Path, binding: str,
            verified_at: str, knowledge: str | None) -> None:
    verdict, reason = ("stale", "; ".join(reasons)) if reasons else ("valid", "")
    if reference:
        print(f"run_id={run_id}")
        print(f"reference run of {slug}: verdict {verdict}" + (f" ({reason})" if reason else ""))
    else:
        _append_row(index, {"slug": slug, "run_id": run_id, "binding": binding, "verdict": verdict,
                            "reason": reason, "verified_at": verified_at, "knowledge": knowledge})
        print(f"{slug}: run {run_id} verdict {verdict}" + (f" ({reason})" if reason else ""))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Launch a held-out case on its frozen copy")
    parser.add_argument("case_dir", type=Path, nargs="+",
                        help="the held-out case dir(s) (alert.json, case.yaml); several: one variant, one copy")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--index", type=Path, help="the held-out index (JSON Lines) to append to")
    parser.add_argument("--freezes-dir", type=Path, default=None,
                        help="default: <case dir>/../freezes")
    parser.add_argument("--parts-dir", type=Path, default=os.environ.get("V2_FROZEN_PARTS_DIR"),
                        help="the lab disk path parts live under (D8); default $V2_FROZEN_PARTS_DIR")
    parser.add_argument("--knowledge-commit", default=None, metavar="SHA")
    parser.add_argument("--reference", action="store_true",
                        help="a labelling run: serve the copy, write no row, print the run id")
    parser.add_argument("--parallel", type=int, default=1, metavar="N",
                        help="agents run at once, in waves (default 1)")
    parser.add_argument("--lock-token", default=None,
                        help="the token of the frozen-engine lock make-a-case holds")
    args = parser.parse_args(argv)
    if not args.parts_dir or (not args.reference and not args.index):
        parser.error("--parts-dir (or $V2_FROZEN_PARTS_DIR) and, unless --reference, --index are required")
    from lab_ops import LabOps
    ops = LabOps.from_environment()
    try:
        launch_batch(args.case_dir, freezes_dir=args.freezes_dir or args.case_dir[0].resolve().parent / "freezes",
               tenant_settings=frozen_copy.tenant_settings_dir(), index=args.index or Path(os.devnull),
               parts_dir=args.parts_dir, lock_store=lock.DockerLockStore(), es=ops.frozen_es(), ops=ops,
               tenant=args.tenant, knowledge=args.knowledge_commit, reference=args.reference,
               lock_token=args.lock_token, parallel=args.parallel)
    except (lock.LockError, LaunchRefused, frozen_copy.CopyRefused, RunDied) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 4
    except TeardownFailed as exc:
        print(f"teardown failed: {exc}", file=sys.stderr)
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
