#!/usr/bin/env python3
"""PostToolUse hook: Track tool call budget per investigation run.

Counts tool calls and subagent spawns per run, printing warnings to
stderr when usage crosses 75% or 100% of configured limits. Also
checks wall-clock elapsed time.

This hook is **warning-only** — it always exits 0 and never blocks the
agent. The warnings provide observability for operators; hard enforcement
can be added later by switching to exit code 2.

Run identification uses session_id from hook input, mapped to a run
directory via {runs_dir}/.sessions/{session_id}.json. The mapping is
created on first invocation by associating the session with the most
recent unmapped active run.

Exit codes:
    0 - Always (budget warnings should never block the agent)
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.frontmatter import parse_yaml_frontmatter  # noqa: E402
from schemas.budget import DEFAULT_LIMITS, WARNING_THRESHOLD, make_budget_state  # noqa: E402


def get_runs_dir() -> Path:
    """Get the runs directory. Configurable via SOC_AGENT_RUNS_DIR env var."""
    return Path(os.environ.get("SOC_AGENT_RUNS_DIR", str(SOC_AGENT_ROOT / "runs")))


def parse_yaml_config(path: Path) -> dict:
    """Parse a plain YAML config file by wrapping it for the frontmatter parser."""
    if not path.exists():
        return {}
    text = path.read_text()
    wrapped = f"---\n{text}\n---"
    return parse_yaml_frontmatter(wrapped)


def _find_unmapped_active_run(runs_dir: Path, sessions_dir: Path) -> Path | None:
    """Find the most recent run dir with meta.json that has no session mapping.

    A run is considered active if it has no state.json or its phase is not
    CONCLUDE. Runs that already have a session mapping file pointing to them
    are excluded.
    """
    # Collect all run_dirs already mapped to a session.
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
        # Check if run is still active (not CONCLUDE).
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
    # Most recently modified wins.
    return max(candidates, key=lambda d: d.stat().st_mtime)


def resolve_run_dir(session_id: str, runs_dir: Path) -> tuple[Path | None, str]:
    """Map a session_id to its investigation run directory.

    Returns (run_dir, signature_id) or (None, "") if no active run found.

    On first call for a session, creates the mapping file by associating
    the session with the most recent unmapped active run.
    """
    sessions_dir = runs_dir / ".sessions"
    mapping_path = sessions_dir / f"{session_id}.json"

    # Fast path: mapping already exists.
    if mapping_path.exists():
        try:
            data = json.loads(mapping_path.read_text())
            run_dir = Path(data["run_dir"])
            if run_dir.exists():
                return run_dir, data.get("signature_id", "")
        except Exception:
            pass

    # Slow path: find an unmapped active run and create the mapping.
    run_dir = _find_unmapped_active_run(runs_dir, sessions_dir)
    if run_dir is None:
        return None, ""

    # Read signature_id from meta.json.
    signature_id = ""
    try:
        meta = json.loads((run_dir / "meta.json").read_text())
        signature_id = meta.get("signature_id", "")
    except Exception:
        pass

    # Persist the mapping.
    sessions_dir.mkdir(parents=True, exist_ok=True)
    mapping_path.write_text(json.dumps({
        "run_dir": str(run_dir),
        "signature_id": signature_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }))

    return run_dir, signature_id


def load_limits(signature_id: str) -> dict:
    """Load budget limits: defaults overlaid with per-signature overrides."""
    limits = dict(DEFAULT_LIMITS)

    # Layer 1: config/budget-defaults.yaml
    defaults_path = SOC_AGENT_ROOT / "config" / "budget-defaults.yaml"
    defaults = parse_yaml_config(defaults_path)
    for key in limits:
        if key in defaults and isinstance(defaults[key], int):
            limits[key] = defaults[key]

    # Layer 2: per-signature permissions.yaml budget section
    if signature_id:
        perms_path = (
            SOC_AGENT_ROOT / "config" / "signatures" / signature_id / "permissions.yaml"
        )
        perms = parse_yaml_config(perms_path)
        budget_overrides = perms.get("budget")
        if isinstance(budget_overrides, dict):
            for key in limits:
                if key in budget_overrides and isinstance(budget_overrides[key], int):
                    limits[key] = budget_overrides[key]

    return limits


def load_or_create_budget(run_dir: Path, run_id: str) -> dict:
    """Read budget.json from run_dir, or create a fresh one."""
    budget_path = run_dir / "budget.json"
    if budget_path.exists():
        try:
            return json.loads(budget_path.read_text())
        except Exception:
            pass
    return make_budget_state(run_id)


def save_budget(run_dir: Path, budget: dict) -> None:
    """Write budget.json to run_dir."""
    budget_path = run_dir / "budget.json"
    budget_path.write_text(json.dumps(budget, indent=2))


def check_budgets(budget: dict, limits: dict) -> list[str]:
    """Check budget counters against limits. Returns warning messages."""
    warnings = []
    now = datetime.now(timezone.utc)

    # Wall-clock timeout
    max_seconds = limits.get("wall_clock_timeout", DEFAULT_LIMITS["wall_clock_timeout"])
    try:
        started = datetime.fromisoformat(budget["started_at"])
        elapsed = (now - started).total_seconds()
        ratio = elapsed / max_seconds if max_seconds > 0 else 0
        if ratio >= 1.0:
            warnings.append(
                f"Budget exceeded: wall_clock at {int(elapsed)}s/{max_seconds}s. "
                "Investigation should conclude with current evidence."
            )
        elif ratio >= WARNING_THRESHOLD:
            warnings.append(
                f"Budget warning: wall_clock at {int(elapsed)}s/{max_seconds}s "
                f"({int(ratio * 100)}%). Consider wrapping up."
            )
    except Exception:
        pass

    # Tool calls
    max_calls = limits.get("max_tool_calls", DEFAULT_LIMITS["max_tool_calls"])
    calls = budget.get("tool_calls", 0)
    if max_calls > 0:
        ratio = calls / max_calls
        if ratio >= 1.0:
            warnings.append(
                f"Budget exceeded: tool_calls at {calls}/{max_calls}. "
                "Investigation should conclude with current evidence."
            )
        elif ratio >= WARNING_THRESHOLD:
            warnings.append(
                f"Budget warning: tool_calls at {calls}/{max_calls} "
                f"({int(ratio * 100)}%). Consider wrapping up."
            )

    # Subagent spawns
    max_spawns = limits.get("max_subagent_spawns", DEFAULT_LIMITS["max_subagent_spawns"])
    spawns = budget.get("subagent_spawns", 0)
    if max_spawns > 0:
        ratio = spawns / max_spawns
        if ratio >= 1.0:
            warnings.append(
                f"Budget exceeded: subagent_spawns at {spawns}/{max_spawns}. "
                "Investigation should conclude with current evidence."
            )
        elif ratio >= WARNING_THRESHOLD:
            warnings.append(
                f"Budget warning: subagent_spawns at {spawns}/{max_spawns} "
                f"({int(ratio * 100)}%). Consider wrapping up."
            )

    return warnings


def main():
    try:
        raw = sys.stdin.read()
        hook_data = json.loads(raw)
    except Exception:
        sys.exit(0)

    session_id = hook_data.get("session_id")
    if not session_id:
        sys.exit(0)

    runs_dir = get_runs_dir()
    run_dir, signature_id = resolve_run_dir(session_id, runs_dir)
    if run_dir is None:
        sys.exit(0)

    # Load or create budget state.
    run_id = run_dir.name
    budget = load_or_create_budget(run_dir, run_id)

    # Increment counters.
    budget["tool_calls"] = budget.get("tool_calls", 0) + 1
    tool_name = hook_data.get("tool_name", "")
    if tool_name == "Agent":
        budget["subagent_spawns"] = budget.get("subagent_spawns", 0) + 1

    save_budget(run_dir, budget)

    # Check limits and print warnings.
    limits = load_limits(signature_id)
    warnings = check_budgets(budget, limits)
    for warning in warnings:
        print(f"\u26a0 {warning}", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
