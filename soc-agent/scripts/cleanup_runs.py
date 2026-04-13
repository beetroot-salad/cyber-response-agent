#!/usr/bin/env python3
"""Prune aged run directories and JSONL log entries.

Deletes run/{uuid}/ directories older than SOC_AGENT_RUN_MAX_AGE_DAYS and
filters stale lines from the three cross-run JSONL logs.

Usage:
    python3 scripts/cleanup_runs.py [--dry-run] [--verbose]

Environment variables (all optional — defaults apply when unset):
    SOC_AGENT_RUN_MAX_AGE_DAYS    (default 90)   — run directories
    SOC_AGENT_AUDIT_MAX_AGE_DAYS  (default 365)  — audit.jsonl + tool_audit.jsonl
    SOC_AGENT_TRACE_MAX_AGE_DAYS  (default 30)   — tool_trace.jsonl

Exit codes:
    0 — success (including dry-run)
    1 — fatal error (bad config, permission error)

Known limitation — JSONL race window:
    clean_jsonl() reads the file, filters expired lines, then atomically
    replaces it via a .tmp file (os.replace).  If a hook appends a new line
    to the JSONL file in the interval between the read and the os.replace,
    that line will be silently dropped.  At daily-cron frequency the window
    is milliseconds and the probability is low (~1% at 1000 alerts/day), but
    it is not zero.  Schedule cleanup during low-activity windows (e.g. 2am)
    to minimize exposure.
    # TODO: add fcntl.flock on POSIX if concurrent writes become a concern —
    # requires locking in investigation_summary.py and audit_tool_calls.py too.
"""

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.retention import load_retention_policy  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_runs_dir() -> Path:
    """Get the runs directory. Configurable via SOC_AGENT_RUNS_DIR env var."""
    return Path(os.environ.get("SOC_AGENT_RUNS_DIR", str(SOC_AGENT_ROOT / "runs")))


def is_dir_expired(dir_path: Path, cutoff: datetime) -> bool:
    """Return True if dir_path's mtime is before cutoff (strictly less than)."""
    mtime = datetime.fromtimestamp(dir_path.stat().st_mtime, tz=timezone.utc)
    return mtime < cutoff


def parse_jsonl_timestamp(line: str) -> datetime | None:
    """Parse the 'timestamp' field from a JSONL line.

    Returns None on any failure — malformed JSON, missing field, or
    unparseable timestamp string.  Callers treat None as 'keep the line'
    (conservative: never silently drop what we can't date).
    """
    try:
        obj = json.loads(line)
        ts_str = obj.get("timestamp")
        if not ts_str:
            return None
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Cleanup routines
# ---------------------------------------------------------------------------

def clean_run_dirs(
    runs_dir: Path,
    cutoff: datetime,
    dry_run: bool,
    verbose: bool,
) -> tuple[int, int]:
    """Delete run directories whose mtime predates cutoff.

    Skips entries that are not directories and names starting with '.'
    (e.g. .gitkeep's parent).  Wraps each rmtree in try/except so a single
    unreadable directory does not abort the entire sweep.

    Returns (deleted_count, skipped_count).
    """
    if not runs_dir.exists():
        return 0, 0

    deleted = skipped = 0
    for entry in runs_dir.iterdir():
        if not entry.is_dir() or entry.name.startswith("."):
            continue

        # Safety check — only delete directories directly under runs_dir.
        # Protects against a misconfigured SOC_AGENT_RUNS_DIR pointing at /.
        if entry.parent.resolve() != runs_dir.resolve():
            continue

        if is_dir_expired(entry, cutoff):
            if verbose:
                mtime = datetime.fromtimestamp(entry.stat().st_mtime, tz=timezone.utc)
                print(f"  [DELETE] {entry.name}  (mtime {mtime.date()})")
            if not dry_run:
                try:
                    shutil.rmtree(entry)
                except OSError as e:
                    print(f"warning: could not remove {entry}: {e}", file=sys.stderr)
                    skipped += 1
                    continue
            deleted += 1
        else:
            if verbose:
                mtime = datetime.fromtimestamp(entry.stat().st_mtime, tz=timezone.utc)
                print(f"  [KEEP]   {entry.name}  (mtime {mtime.date()})")
            skipped += 1

    return deleted, skipped


def clean_jsonl(
    path: Path,
    cutoff: datetime,
    dry_run: bool,
    verbose: bool,
) -> tuple[int, int]:
    """Filter lines older than cutoff from a JSONL file.

    Uses an atomic write (tmp file + os.replace) so concurrent readers always
    see a complete file.

    Conservative: lines with missing or unparseable timestamps are kept, not
    dropped — we never silently discard what we cannot date.

    See module docstring for the known race window between read and os.replace.

    Returns (kept_count, dropped_count).  Blank lines pass through and are
    not counted.
    """
    if not path.exists():
        return 0, 0

    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)

    kept: list[str] = []
    dropped = 0

    for line in lines:
        stripped = line.strip()
        if not stripped:
            kept.append(line)  # blank lines pass through
            continue

        ts = parse_jsonl_timestamp(stripped)
        if ts is None or ts >= cutoff:
            kept.append(line)
            if verbose and ts is not None:
                print(f"  [KEEP]   {path.name}  ts={ts.date()}")
            elif verbose:
                print(f"  [KEEP]   {path.name}  (no/unparseable timestamp — conservative keep)")
        else:
            dropped += 1
            if verbose:
                print(f"  [DROP]   {path.name}  ts={ts.date()}")

    if dropped > 0 and not dry_run:
        tmp = path.with_suffix(".jsonl.tmp")
        try:
            tmp.write_text("".join(kept), encoding="utf-8")
            os.replace(tmp, path)
        except OSError as e:
            # Clean up tmp if the replace failed; original file is untouched.
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            print(f"warning: could not rewrite {path.name}: {e}", file=sys.stderr)
            return len(kept) - dropped, 0  # report as if nothing dropped

    kept_count = sum(1 for l in kept if l.strip())  # blank lines excluded from count
    return kept_count, dropped


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Prune aged soc-agent run directories and JSONL log entries.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be deleted/filtered without making any changes.",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-item decisions (each dir kept/deleted, each JSONL line).",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        policy = load_retention_policy()  # exits 1 on bad config
        runs_dir = get_runs_dir()
        now = datetime.now(timezone.utc)

        run_cutoff   = now - timedelta(days=policy.run_max_age_days)
        audit_cutoff = now - timedelta(days=policy.audit_max_age_days)
        trace_cutoff = now - timedelta(days=policy.trace_max_age_days)

        if args.dry_run:
            print("[dry-run] No changes will be made.")

        if args.verbose:
            print(f"runs dir:     {runs_dir}")
            print(f"run cutoff:   {run_cutoff.date()} ({policy.run_max_age_days}d)")
            print(f"audit cutoff: {audit_cutoff.date()} ({policy.audit_max_age_days}d)")
            print(f"trace cutoff: {trace_cutoff.date()} ({policy.trace_max_age_days}d)")

        del_dirs, skip_dirs = clean_run_dirs(
            runs_dir, run_cutoff, args.dry_run, args.verbose,
        )
        kept_a,  drop_a  = clean_jsonl(
            runs_dir / "audit.jsonl",      audit_cutoff, args.dry_run, args.verbose,
        )
        kept_ta, drop_ta = clean_jsonl(
            runs_dir / "tool_audit.jsonl", audit_cutoff, args.dry_run, args.verbose,
        )
        kept_tr, drop_tr = clean_jsonl(
            runs_dir / "tool_trace.jsonl", trace_cutoff, args.dry_run, args.verbose,
        )

        verb = "Would delete" if args.dry_run else "Deleted"
        print(
            f"{verb} {del_dirs} run dir(s) ({skip_dirs} skipped), "
            f"filtered {drop_a}/{drop_ta}/{drop_tr} lines from "
            f"audit.jsonl / tool_audit.jsonl / tool_trace.jsonl"
        )

    except SystemExit:
        raise
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
