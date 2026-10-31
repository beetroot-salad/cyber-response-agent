#!/usr/bin/env python3
"""Launch one held-out case against its freeze and write the run's index row (#1347 D10/O6/O9).

Every scored held-out run is started here, under the frozen engine's lab-server lock:

    take the lock -> read freeze.yaml -> check every part's digest (missing or different:
    refuse, no run, no row) -> load a fresh frozen copy -> run the agent with --as-of,
    --arrived-by and --no-learn, under a Docker config whose playground context points at the
    frozen engine -> recompute the fingerprint with the shared cut clause -> tear the copy down
    -> append {slug, run_id, freeze, verdict, reason, verified_at} -> release the lock

`freeze` is the freeze digest: bare hex sha256 of the parsed freeze.yaml as sorted-key compact
JSON, so comments, key order and line endings do not change it. A run that dies before printing
`run_id=` gets no row; the operator re-launches. `--reference` serves the freeze the same way but
appends no row and prints the run id, for labelling (O8); it works before `confirmed` is filled.

    defender/.venv/bin/python playground-v2/scripts/launch_frozen.py \\
        evaluations/fixtures/held_out/<slug> --tenant "$TENANT_ID" --index F \\
        --parts-dir <lab disk path> [--knowledge-commit K] [--reference]

`ops=`, `run_fn=`, `lock_store=` and `clock=` are injectable so tests never need the live stack.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
# The repo root too: the freeze digest and the YAML loader are the scorer's own.
for _path in (HERE, HERE.parent, REPO):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from chaos import lock  # noqa: E402
from evaluations import held_out  # noqa: E402
from lab_ops import LabOps, sha256_file  # noqa: E402

PLAYGROUND_CONTEXT = "soc-playground"


class LaunchRefused(RuntimeError):
    """The case cannot be served as frozen: a part is missing or altered, or the freeze is not
    ready. Nothing ran and no row was written."""


class RunDied(RuntimeError):
    """The agent ended without announcing a run id; there is nothing to bind a row to."""


class WallClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


def freeze_digest(parsed: Any) -> str:
    """The freeze digest the scorer compares rows against, computed by the scorer's own function
    so a row's digest and the case's can never drift apart. A value canonical JSON cannot carry
    (an unquoted YAML timestamp, say) refuses."""
    try:
        return held_out.freeze_digest(parsed)
    except (TypeError, ValueError) as exc:
        raise LaunchRefused(f"freeze.yaml holds a value canonical JSON cannot carry: {exc}") from exc


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _check_parts(freeze: dict, mine: Path) -> None:
    problems = []
    for name, digest in sorted((freeze.get("parts") or {}).items()):
        path = mine / name
        want = str(digest).removeprefix("sha256:")
        if not path.is_file():
            problems.append(f"{name} is missing ({path})")
        elif sha256_file(path) != want:
            problems.append(f"{name} differs from its digest ({path})")
    if problems:
        raise LaunchRefused("stale freeze parts, not launching: " + "; ".join(problems))


def _docker_config(operator_config: Path, work_dir: Path, docker_host: str) -> Path:
    """A copy of the operator's Docker config with only the playground context repointed (D2).
    The directory name is random: the run's shell can see DOCKER_CONFIG (P4)."""
    target = Path(work_dir) / f"docker-{secrets.token_hex(6)}"
    shutil.copytree(operator_config, target, symlinks=True)
    repointed = 0
    for meta in sorted((target / "contexts" / "meta").glob("*/meta.json")):
        data = json.loads(meta.read_text())
        if data.get("Name") != PLAYGROUND_CONTEXT:
            continue
        data.setdefault("Endpoints", {}).setdefault("docker", {})["Host"] = docker_host
        meta.write_text(json.dumps(data))
        repointed += 1
    if repointed != 1:
        shutil.rmtree(target, ignore_errors=True)
        raise LaunchRefused(f"the operator's Docker config has {repointed} contexts named "
                            f"{PLAYGROUND_CONTEXT!r}; expected one")
    return target


def _run_id(stdout: str) -> Optional[str]:
    first = stdout.splitlines()[0] if stdout else ""
    if not first.startswith("run_id="):
        return None
    return first.removeprefix("run_id=").strip() or None


def _verdict(want: dict, got: dict) -> tuple[str, str]:
    want = {k: [int(x) for x in v] for k, v in (want or {}).items()}
    got = {k: [int(x) for x in v] for k, v in (got or {}).items()}
    if want == got:
        return "valid", ""
    changed = sorted(k for k in set(want) & set(got) if want[k] != got[k])
    added = sorted(set(got) - set(want))
    removed = sorted(set(want) - set(got))
    parts = [f"{label} {len(keys)} bucket(s), first {keys[0]}"
             for label, keys in (("changed", changed), ("added", added), ("removed", removed)) if keys]
    return "stale", "fingerprint differs: " + "; ".join(parts)


def _append_row(index: Path, row: dict) -> None:
    index.parent.mkdir(parents=True, exist_ok=True)
    # Append only: earlier rows are never rewritten. A last row without its newline gets one.
    needs_newline = index.exists() and index.stat().st_size > 0 and \
        not index.read_bytes().endswith(b"\n")
    with open(index, "ab") as fh:
        if needs_newline:
            fh.write(b"\n")
        fh.write((json.dumps(row, sort_keys=True) + "\n").encode())


def _default_run_fn(argv: list[str], env: dict) -> tuple[int, str, str]:
    proc = subprocess.run(argv, env=env, stdout=subprocess.PIPE, text=True)
    sys.stdout.write(proc.stdout)
    return proc.returncode, proc.stdout, ""


def _agent_python() -> str:
    venv = REPO / "defender" / ".venv" / "bin" / "python"
    return str(venv) if venv.exists() else sys.executable


def launch(case_dir: Path, *, index: Path, parts_dir: Path, lock_store: Any, ops: Any,
           run_fn: Any = _default_run_fn, clock: Any = None, work_dir: Path,
           operator_docker_config: Path, tenant: str, reference: bool = False,
           knowledge_commit: Optional[str] = None) -> str:
    """Serve one frozen run of `case_dir`; returns its run id."""
    case_dir, parts_dir, index = Path(case_dir), Path(parts_dir), Path(index)
    clock = clock if clock is not None else WallClock()
    slug = case_dir.name
    alert = case_dir / "alert.json"

    token = lock.take(lock_store, lock.FROZEN_ENGINE)
    try:
        # The scorer's own loader, so a freeze.yaml one reads the other reads (no aliases).
        from defender._yaml import safe_load
        freeze = safe_load((case_dir / "freeze.yaml").read_text())
        digest = freeze_digest(freeze)
        if not reference and not freeze.get("confirmed"):
            raise LaunchRefused(f"{slug}: freeze.yaml is not confirmed yet; label it against a "
                                "--reference run first")
        _check_parts(freeze, parts_dir / slug)
        as_of, arrived_by = freeze["as_of"], freeze["captured_at"]
        # The post-run check is the production fingerprint unless `ops` brings its own.
        fingerprint_of = getattr(ops, "fingerprint", None) or LabOps().fingerprint

        argv = [_agent_python(), str(REPO / "defender" / "run.py"), str(alert),
                "--tenant", tenant, "--no-learn", "--as-of", as_of, "--arrived-by", arrived_by]
        if knowledge_commit:
            argv += ["--knowledge-commit", knowledge_commit]

        config: Optional[Path] = None
        run_id: Optional[str] = None
        try:
            frozen = ops.load_frozen(parts_dir / slug, as_of)
            config = _docker_config(operator_docker_config, work_dir, frozen["docker_host"])
            # Only DOCKER_CONFIG changes: DOCKER_HOST / DOCKER_CONTEXT stay as the operator has
            # them (every adapter call names its context), and nothing names the freeze (P4).
            env = {**os.environ, "DOCKER_CONFIG": str(config)}
            rc, stdout, _ = run_fn(argv, env)
            run_id = _run_id(stdout)
            if run_id is None:
                raise RunDied(f"{slug}: the agent exited rc={rc} without announcing a run id; "
                              "no row written, re-launch")
            fingerprint = fingerprint_of(freeze["window"], as_of, arrived_by)
            verified_at = _iso(clock.now())
        except BaseException:
            try:
                ops.teardown()
            except Exception as exc:  # the first failure is the one to report
                print(f"teardown after a failed launch also failed: {exc}", file=sys.stderr)
            raise
        finally:
            if config is not None:
                shutil.rmtree(config, ignore_errors=True)
        ops.teardown()

        verdict, reason = _verdict(freeze.get("fingerprint") or {}, fingerprint)
        if reference:
            print(f"run_id={run_id}")
            print(f"reference run of {slug}: verdict {verdict}" + (f" ({reason})" if reason else ""))
            return run_id
        _append_row(index, {"slug": slug, "run_id": run_id, "freeze": digest, "verdict": verdict,
                            "reason": reason, "verified_at": verified_at})
        print(f"{slug}: run {run_id} verdict {verdict}" + (f" ({reason})" if reason else ""))
        return run_id
    finally:
        lock.release(lock_store, lock.FROZEN_ENGINE, token)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Launch a held-out case against its freeze")
    parser.add_argument("case_dir", type=Path, help="the held-out case dir (alert.json, freeze.yaml)")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--index", type=Path, help="the held-out index (JSON Lines) to append to")
    parser.add_argument("--parts-dir", type=Path, default=os.environ.get("V2_FROZEN_PARTS_DIR"),
                        help="the lab disk path parts live under (D8); default $V2_FROZEN_PARTS_DIR")
    parser.add_argument("--knowledge-commit", default=None, metavar="SHA")
    parser.add_argument("--reference", action="store_true",
                        help="a labelling run: serve the freeze, write no row, print the run id")
    parser.add_argument("--work-dir", type=Path, default=None)
    args = parser.parse_args(argv)
    if not args.parts_dir or (not args.reference and not args.index):
        parser.error("--parts-dir (or $V2_FROZEN_PARTS_DIR) and, unless --reference, --index "
                     "are required")
    operator_config = Path(os.environ.get("DOCKER_CONFIG") or Path.home() / ".docker")
    work_dir = args.work_dir or Path(os.environ.get("TMPDIR", "/tmp"))
    try:
        launch(args.case_dir, index=args.index or Path(os.devnull), parts_dir=args.parts_dir,
               lock_store=lock.DockerLockStore(), ops=LabOps(), work_dir=work_dir,
               operator_docker_config=operator_config, tenant=args.tenant,
               reference=args.reference, knowledge_commit=args.knowledge_commit)
    except (lock.LockError, LaunchRefused, RunDied) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
