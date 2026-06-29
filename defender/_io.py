"""Tolerant JSONL reads + atomic writes, shared across learning/, scripts/, runtime/.

One contract for "read a live-appended JSONL queue" and "rewrite a file
atomically", so the copies can't drift apart again. ``read_jsonl_rows`` skips
torn/blank lines (an append interrupted mid-write leaves a half-line — see #446);
``write_atomic`` does the ``tmp → write → os.replace`` dance so a reader never sees
a partial file.

Lives at the ``defender.`` namespace root (no ``__init__.py`` — PEP 420
namespace package), like ``defender._frontmatter`` (see #322/#323), so it is
importable from ``learning/``, ``scripts/``, ``runtime/`` and ``hooks/`` alike —
crucially without the runtime/hooks layers taking a dependency on
``defender.learning`` (the #317 decoupling), where these helpers used to live.
"""
from __future__ import annotations

import json
import os
from pathlib import Path


def read_jsonl_rows(path: Path) -> list[dict]:
    """All rows in a JSONL file (tolerant of blank/malformed lines).

    The single tolerant JSONL reader for the live-appended queues: a torn line
    from an interrupted append is skipped, not raised, so a drain that reads its
    queue never crashes on a half-written record.
    """
    if not path.is_file():
        return []
    rows: list[dict] = []
    for line in path.read_text().splitlines():  # lint-jsonl-read: ok — the canonical tolerant reader
        s = line.strip()
        if not s:
            continue
        try:
            rows.append(json.loads(s))
        except json.JSONDecodeError:
            continue
    return rows


def append_jsonl(path: Path, rows: list[dict]) -> int:
    """Append ``rows`` as JSON lines, creating parent dirs; return the count.

    A no-op (returns 0) on an empty ``rows`` so callers needn't guard.
    """
    if not rows:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    return len(rows)


def write_atomic(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically via a sibling ``.tmp`` + ``os.replace``.

    A concurrent reader sees either the old file or the whole new one, never a
    partial write. Caller owns serialization; the replace itself is atomic on POSIX.
    """
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)
