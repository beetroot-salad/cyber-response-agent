from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from defender._run_paths import RunPaths
from defender.learning.core.config import REPO_ROOT
from defender.learning.tickets import ticket_seeds

HERE = Path(__file__).resolve().parent
PROMPT_PATH = HERE / "forward.md"

_TICKET_CLI = ticket_seeds._TICKET_CLI
_POLICY_FETCH_TIMEOUT = 15
_NO_CITED_POLICY = (
    "(no cited covering policy — none was offered, or the store is unreachable)"
)


def load_run_context(run_id: str, *, runs_dir: Path) -> tuple[str, str]:
    run_dir = runs_dir / run_id
    investigation = RunPaths(run_dir).investigation
    refs = run_dir / "source_refs.yaml"
    if not investigation.is_file():
        raise SystemExit(f"verify_forward: missing investigation.md at {investigation}")
    if not refs.is_file():
        raise SystemExit(f"verify_forward: missing source_refs.yaml at {refs}")
    m = re.search(
        r"^normalized_disposition:\s*[\"']?([^\"'\n#]+?)[\"']?\s*(?:#.*)?$",
        refs.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if not m:
        raise SystemExit(
            f"verify_forward: source_refs.yaml missing normalized_disposition: {refs}"
        )
    return investigation.read_text(encoding="utf-8"), m.group(1).strip()


def expected_disposition(direction: str, recorded: str) -> str:
    if direction == "benign":
        return "benign"
    return recorded


def _cited_case_ids(run_id: str, *, runs_dir: Path) -> list[str]:
    menu = runs_dir / run_id / "past_tickets.txt"
    if not menu.is_file():
        return []
    ids: list[str] = []
    for line in menu.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s.startswith("- "):
            continue
        head = s[2:].split(":", 1)[0].strip()
        if head:
            ids.append(head)
    return ids


def _fetch_closed_resolution(case_id: str) -> str | None:
    cmd = [
        sys.executable, str(_TICKET_CLI), "get-ticket", case_id,
        "--require-closed",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=_POLICY_FETCH_TIMEOUT, cwd=str(REPO_ROOT), encoding="utf-8"
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if proc.returncode != 0:
        return None
    try:
        ticket = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    res = ticket.get("resolution") if isinstance(ticket, dict) else None
    return res if isinstance(res, str) and res.strip() else None


def load_cited_policy(
    run_id: str, *, runs_dir: Path, fetch_fn=_fetch_closed_resolution
) -> str:
    lines = [
        f"- {case_id}: {res}"
        for case_id in _cited_case_ids(run_id, runs_dir=runs_dir)
        if (res := fetch_fn(case_id))
    ]
    if not lines:
        return _NO_CITED_POLICY
    return (
        "Cited covering policies (closed cases; grounded conditions ride in the "
        "resolution):\n" + "\n".join(lines)
    )
