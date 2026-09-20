"""O5 — the scorer's ground truth: one JSON file per activate/revert record.

Gitignored, devcontainer-side (`chaos/ledger/*.json` — see the sibling
`.gitignore`). Values are *stored*, not recomputed: `chaos.ctl.activate`
writes the record once with the mutations it actually pushed, and
`chaos.ctl.revert` stamps `reverted_at` onto the same file rather than
appending a second one, so a ledger_ref always resolves to exactly one
record.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional


def read_records(ledger_dir: Path) -> list[dict[str, Any]]:
    ledger_dir = Path(ledger_dir)
    if not ledger_dir.is_dir():
        return []
    return [json.loads(p.read_text()) for p in sorted(ledger_dir.glob("*.json"))]


def find_record(ledger_dir: Path, ledger_ref: str) -> Optional[dict[str, Any]]:
    path = Path(ledger_dir) / f"{ledger_ref}.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text())


def write_record(ledger_dir: Path, record: dict[str, Any]) -> None:
    ledger_dir = Path(ledger_dir)
    ledger_dir.mkdir(parents=True, exist_ok=True)
    path = ledger_dir / f"{record['ledger_ref']}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True, default=str))
