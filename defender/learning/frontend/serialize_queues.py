"""The queue view: what the learning store holds per tenant, and what the loop set aside (#1278 O2)."""
from __future__ import annotations

import datetime as _dt
from typing import Any

from defender._clock import z_seconds
from pathlib import Path

from defender._io import TEXT_READ_ERRORS, load_json_artifact, read_text_utf8
from defender.jobs.learning_models import KINDS
from defender.learning.core.config import LoopPaths
from defender.learning.core.quarantine import held_archives, quarantine_cap
from defender.learning.frontend.serialize import dump_contract

__all__ = ["build_view", "stamped_view", "dump_contract"]

_PERSON_HOLD = "held until a person moves them — nothing retries a hold"
#: How the page shows each of the store's work-item kinds: its name, its accent and what a hold means. Every kind the
#: store holds has an entry (the page lists them in the store's order, `KINDS`), so a new kind cannot go unlisted.
_PAGE: dict[str, tuple[str, str, str]] = {
    "finding": ("findings", "defender", _PERSON_HOLD),
    "questioner_finding": ("questioner_findings", "learning", _PERSON_HOLD),
    "pitfall": ("pitfalls", "oracle", "declined by the curator — offered again every tick, retired at the offer ceiling"),
    "curation_request": ("curation_requests", "raw", _PERSON_HOLD),
    "feedback_instruction": ("feedback_instructions", "learning", _PERSON_HOLD),
}
#: What the page lists: everything not yet finished (published and skipped items are history).
_LISTED = ("waiting", "in_batch", "held", "dead")


def _str(value: object) -> str:
    return value if isinstance(value, str) else ""


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _channel_view(kind: str, name: str, accent: str, hold_means: str, items: list[Any]) -> dict:
    rows = [
        {"id": i.key, "status": i.status, "reason": i.reason, "batch_id": str(i.batch_id) if i.batch_id else None,
         "pr_number": i.pr_number, "source_run": i.source_run}
        for i in items if i.kind == kind and i.status in _LISTED
    ]
    held = [r["id"] for r in rows if r["status"] == "held"]
    dead = [r for r in rows if r["status"] == "dead"]
    return {
        "name": name,
        "accent": accent,
        "hold_means": hold_means,
        "items": rows,
        "depth": {"waiting": sum(1 for r in rows if r["status"] == "waiting"), "queued": len(rows)},
        "held": {"count": len(held), "ids": held},
        "deadletter": [{"id": r["id"], "reason": _str(r["reason"]), "when": None, "row": {}} for r in dead],
    }


def _json_files(directory: Path) -> tuple[list[tuple[Path, dict]], int]:
    """Every readable `*.json` mapping directly under `directory`, plus how many were not.

    For the tainted-worktree archive, which lives off the worktree base and is no state-tree
    record (N6). An unlistable directory counts as one unreadable — listed with `iterdir`
    because `Path.glob` swallows the `PermissionError` and answers "empty"."""
    try:
        if not directory.is_dir():
            return [], 0
        found = sorted(p for p in directory.iterdir() if p.name.endswith(".json"))
    except OSError:
        return [], 1
    out: list[tuple[Path, dict]] = []
    unreadable = 0
    for path in found:
        try:
            value, err = load_json_artifact(read_text_utf8(path))
        except TEXT_READ_ERRORS:
            unreadable += 1
            continue
        if err is not None or not isinstance(value, dict):
            unreadable += 1
            continue
        out.append((path, value))
    return out, unreadable


def _tainted(paths: LoopPaths) -> dict:
    """The tainted-worktree archive.

    Rows come from manifests (tarballs stay inert; unpacking is an operator act), but `held` is
    the writer's own archive count against its cap: an archive with a missing or torn manifest
    still spends a slot. `held` is null when unlistable, so the page shows "?". `verdict: {}`
    means no scan was recorded, not clean. `dir` is included because it lives off the repo root,
    not the state root."""
    found, unreadable = _json_files(paths.quarantine_dir)
    try:
        held: int | None = held_archives(paths.quarantine_dir)
    except OSError:
        held = None
    rows: list[dict] = []
    for _path, m in found:
        findings = m.get("findings")
        verdict = m.get("verdict")
        rows.append({
            "batch_id": _str(m.get("batch_id")),
            "archive": _str(m.get("archive")),
            "quarantined_at": _opt_str(m.get("quarantined_at")),
            "label": _str(m.get("label")),
            "taint": _str(m.get("taint")),
            "cause": _opt_str(m.get("cause")),
            "verdict": verdict if isinstance(verdict, dict) else {},
            "findings": len(findings) if isinstance(findings, list) else 0,
        })
    rows.sort(key=lambda r: r["quarantined_at"] or "", reverse=True)
    return {
        "dir": str(paths.quarantine_dir), "cap": quarantine_cap(), "held": held,
        "rows": rows, "unreadable": unreadable,
    }


def build_view(paths: LoopPaths, store: Any) -> dict:  # lint-dup: ok — serialize.build_view builds the lessons page from the corpus; this builds the queue page from the store. Same name by design: build.py calls each by module.
    """The contract over the tenant `paths` names: its work items from `store` (the sync facade), and the tainted-worktree
    archive (not a queue). No clock (see `stamped_view`); a store that cannot be read raises, so the build fails."""
    items = store.work(str(paths.tenant.id))  # type: ignore[union-attr]
    return {
        "channels": [_channel_view(kind, *_PAGE[kind], items) for kind in KINDS],
        "quarantine": {"tainted": _tainted(paths)},
    }


def stamped_view(paths: LoopPaths, store: Any = None) -> dict:  # lint-dup: ok — serialize.stamped_view stamps the lessons view; this stamps the queue view. Same name by design, see build_view.
    """`build_view` plus the build time. With no `store` one is opened from `DEFENDER_DATABASE_DSN`, so an unreachable
    store stops the build instead of producing an empty page."""
    if store is None:
        from defender.learning.core.store_tick import opened_store

        with opened_store() as opened:
            view = build_view(paths, opened)
    else:
        view = build_view(paths, store)
    view["generated_at"] = z_seconds(_dt.datetime.now(_dt.UTC))
    return view
