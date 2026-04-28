#!/usr/bin/env python3
"""Single Stop-event entrypoint — composes the Stop-stage steps in order.

plugin.json registers exactly one Stop hook entry pointing at this script.
It reads the Stop payload once from stdin, then invokes each step module's
`main(payload)` function in explicit order:

    1. investigation_summary — append outcome row to runs/audit.jsonl
    2. close_ticket_action   — deterministic close-ticket dispatch

Ordering is guaranteed because it's composed in Python, not delegated to
the harness's hook-serialization semantics. Two hooks touching the same
run directory in undefined order would be a race; composing them in one
entrypoint removes the race.

Every step is wrapped in try/except so a failure in one does not prevent
the next from running. The handler always exits 0 — a broken Stop step
must never crash the agent session.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts import close_ticket_action, investigation_summary  # noqa: E402
from hooks.scripts.run_context import get_runs_dir, resolve_run_dir  # noqa: E402


def _run_step(name: str, func, payload: dict) -> None:
    try:
        func(payload)
    except Exception as exc:  # noqa: BLE001 — must never raise out of the handler
        print(f"stop_handler: {name} raised: {exc!r}", file=sys.stderr)


def _maybe_spawn_postmortem(payload: dict) -> None:
    """Detached-spawn the post-mortem lead-pool normalizer if the run
    produced any ad-hoc lead invocations.

    Cheap pre-check (no subprocess) before launching: read
    `investigation.md` and run `has_ad_hoc_leads` in-process. Skip the
    spawn entirely if the run produced no ad-hoc findings — the common
    case for benign / catalog-only investigations.

    The spawn itself is fire-and-forget. Parent must not block on the
    LLM-driven catalog edits — agent termination is the priority.
    """
    session_id = payload.get("session_id", "")
    if not session_id:
        return
    run_dir, _ = resolve_run_dir(session_id, get_runs_dir())
    if run_dir is None:
        return
    inv_path = run_dir / "investigation.md"
    meta_path = run_dir / "meta.json"
    if not (inv_path.exists() and meta_path.exists()):
        return
    try:
        meta = json.loads(meta_path.read_text())
    except Exception:
        return
    signature_id = meta.get("signature_id")
    if not isinstance(signature_id, str) or "-" not in signature_id:
        return
    vendor = signature_id.split("-", 1)[0]

    from scripts.postmortem.leads.extract import has_ad_hoc_leads
    if not has_ad_hoc_leads(inv_path.read_text(), vendor):
        return

    out_dir = get_runs_dir() / "postmortem" / run_dir.name / "leads"
    out_dir.mkdir(parents=True, exist_ok=True)
    log_handle = open(out_dir / "run.log", "ab")
    subprocess.Popen(
        [
            sys.executable,
            "-m", "scripts.postmortem.leads.run",
            "--run-dir", str(run_dir),
            "--out-dir", str(out_dir),
        ],
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        close_fds=True,
        cwd=str(SOC_AGENT_ROOT),
    )


def main() -> None:
    raw = ""
    try:
        if not sys.stdin.isatty():
            raw = sys.stdin.read()
    except Exception:
        raw = ""

    payload: dict = {}
    if raw.strip():
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {}
        if isinstance(parsed, dict):
            payload = parsed

    _run_step("investigation_summary", investigation_summary.main, payload)
    _run_step("close_ticket_action", close_ticket_action.main, payload)
    _run_step("postmortem_leads", _maybe_spawn_postmortem, payload)


if __name__ == "__main__":
    main()
    sys.exit(0)
