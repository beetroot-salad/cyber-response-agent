"""Shared run-directory resolution for hooks and scripts.

Hooks need to answer two recurring questions: "where is the runs directory?"
and "given a PostToolUse event, which run directory (if any) is it touching?"
This module is the single source of truth for both.
"""

import os
import re
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
