"""Shared run-directory resolution for hooks and scripts.

Hooks need to answer three recurring questions: "where is the runs directory?",
"given a PostToolUse event, which run directory (if any) is it touching?", and
"given a Stop-stage session_id, which run does it belong to?". This module is
the single source of truth for all three.
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent

_BASH_INV_PATH_RE = re.compile(r"([^\s'\"<>|&;()`$]*investigation\.md)")


def get_runs_dir() -> Path:
    """Return the configured runs directory (env override or default)."""
    return Path(os.environ.get("SOC_AGENT_RUNS_DIR", str(SOC_AGENT_ROOT / "runs")))


def extract_run_dir_from_path(file_path: str | Path | None) -> Path | None:
    """Return the run directory if `file_path` points at investigation.md
    inside a direct child of the runs directory, else None.

    Runs are flat one-level subdirectories of `runs_dir`. Anything deeper
    (e.g. `runs/foo/bar/investigation.md`) is rejected — the caller is
    looking at something other than a real run.
    """
    if not file_path:
        return None
    path = Path(file_path)
    if path.name != "investigation.md":
        return None
    run_dir = path.parent
    if run_dir.parent != get_runs_dir():
        return None
    return run_dir


def extract_run_dir(hook_data: dict) -> Path | None:
    """Resolve the run directory for a PostToolUse event, or None if the
    event doesn't target an investigation.md inside a run directory.

    Handles three tool shapes:
    - Write/Edit: read `tool_input.file_path` directly.
    - Bash: parse the command for an `investigation.md` path. This catches
      `cat >> {run}/investigation.md <<EOF` style appends used by
      infer_state's broader matcher.

    For hooks that only care about Write/Edit (and use an `if` filter to
    narrow the matcher), the Bash branch never fires in practice.
    """
    tool_name = hook_data.get("tool_name", "")
    tool_input = hook_data.get("tool_input", {})

    if tool_name in ("Write", "Edit"):
        return extract_run_dir_from_path(tool_input.get("file_path"))

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if "investigation.md" not in command:
            return None
        m = _BASH_INV_PATH_RE.search(command)
        if not m:
            return None
        return extract_run_dir_from_path(m.group(1))

    return None


def _find_unmapped_active_run(runs_dir: Path, sessions_dir: Path) -> Path | None:
    """Find the most recent run dir with meta.json that has no session mapping.

    A run is considered active if it has no state.json or its phase is not
    CONCLUDE. Runs that already have a session mapping file pointing to them
    are excluded.
    """
    mapped_run_dirs: set[str] = set()
    if sessions_dir.exists():
        for sf in sessions_dir.iterdir():
            if sf.suffix == ".json":
                try:
                    data = json.loads(sf.read_text())
                    mapped_run_dirs.add(data.get("run_dir", ""))
                except Exception:
                    continue

    candidates = []
    for d in runs_dir.iterdir():
        if not d.is_dir() or not (d / "meta.json").exists():
            continue
        if str(d) in mapped_run_dirs:
            continue
        state_path = d / "state.json"
        if state_path.exists():
            try:
                state = json.loads(state_path.read_text())
                if state.get("phase") == "CONCLUDE":
                    continue
            except Exception:
                pass
        candidates.append(d)

    if not candidates:
        return None
    return max(candidates, key=lambda d: d.stat().st_mtime)


def resolve_run_dir(session_id: str, runs_dir: Path) -> tuple[Path | None, str]:
    """Map a session_id to its investigation run directory.

    Returns (run_dir, signature_id) or (None, "") if no active run found.

    On first call for a session, creates the mapping file by associating
    the session with the most recent unmapped active run. Session-anchored
    resolution is stable under concurrent runs where an mtime-based fallback
    is not.
    """
    sessions_dir = runs_dir / ".sessions"
    mapping_path = sessions_dir / f"{session_id}.json"

    if mapping_path.exists():
        try:
            data = json.loads(mapping_path.read_text())
            run_dir = Path(data["run_dir"])
            if run_dir.exists():
                return run_dir, data.get("signature_id", "")
        except Exception:
            pass

    run_dir = _find_unmapped_active_run(runs_dir, sessions_dir)
    if run_dir is None:
        return None, ""

    signature_id = ""
    try:
        meta = json.loads((run_dir / "meta.json").read_text())
        signature_id = meta.get("signature_id", "")
    except Exception:
        pass

    sessions_dir.mkdir(parents=True, exist_ok=True)
    mapping_path.write_text(json.dumps({
        "run_dir": str(run_dir),
        "signature_id": signature_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }))

    return run_dir, signature_id
