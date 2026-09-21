"""O5 — the scorer's ground truth: one JSON file per activation.

Gitignored, devcontainer-side (`chaos/ledger/*.json` — see the sibling
`.gitignore`). A record is written *before* the first mutation reaches the
stack (status `pending`, carrying the before-state of every resource it is
about to touch) and rewritten as each resource lands, so at no moment is
there a live fault with no record pointing at it. `chaos.ctl.revert` stamps
`reverted_at` onto the same file rather than appending a second one, so a
ledger_ref always resolves to exactly one record.

Writes are atomic (temp file + rename): an interrupted write can leave the
previous version of a record, never a truncated one.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional


def read_ledger(ledger_dir: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Every parseable record, plus {filename: error} for the ones that are
    not. One hand-edited file must not take `status` and `revert --all`
    down with it — the valid records still need reverting."""
    ledger_dir = Path(ledger_dir)
    if not ledger_dir.is_dir():
        return [], {}
    records: list[dict[str, Any]] = []
    malformed: dict[str, str] = {}
    for path in sorted(ledger_dir.glob("*.json")):
        try:
            record = json.loads(path.read_text())
            if not isinstance(record, dict) or "ledger_ref" not in record:
                raise ValueError("not a ledger record (no ledger_ref)")
            records.append(record)
        except (ValueError, OSError) as exc:
            malformed[path.name] = str(exc)
    return records, malformed


def read_records(ledger_dir: Path) -> list[dict[str, Any]]:
    return read_ledger(ledger_dir)[0]


def find_record(ledger_dir: Path, ledger_ref: str) -> Optional[dict[str, Any]]:
    path = Path(ledger_dir) / f"{ledger_ref}.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text())


def write_record(ledger_dir: Path, record: dict[str, Any]) -> None:
    ledger_dir = Path(ledger_dir)
    ledger_dir.mkdir(parents=True, exist_ok=True)
    path = ledger_dir / f"{record['ledger_ref']}.json"
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True, default=str))
    os.replace(tmp, path)


def delete_record(ledger_dir: Path, ledger_ref: str) -> None:
    """Only for an activation that never landed and was fully rolled back —
    a failed injection is not an injection, so it leaves no ground truth."""
    path = Path(ledger_dir) / f"{ledger_ref}.json"
    if path.is_file():
        path.unlink()
