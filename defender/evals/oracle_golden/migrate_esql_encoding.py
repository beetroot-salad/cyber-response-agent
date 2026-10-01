#!/usr/bin/env python3
"""Re-encode the golden corpus's ES|QL payloads to production's positional shape.

The `esql` verb and `controls.py` (via the shared `esql_payload` shaper) emit `values` as
the wire sends them: bare-array rows, cell `i` bound to `columns[i]`. Re-running
`controls.py` only regenerates `hidden/controls/`, so any dict-row payloads left under
`hidden/observed/` would give one judge prompt two encodings of the same data.

This re-encodes every ES|QL payload under `cases/*/hidden/{observed,controls}/**/*.json`
from dict rows to positional rows, losslessly (re-zipping by `columns[].name` reproduces
the original) and minimally (a file keeps its own serialization; a file with nothing to
migrate is untouched). It is idempotent.

Payloads are found by shape (a dict carrying `query`, `columns`, `row_count` and
`values`), never by a list of known positions, so a payload in a new position is not
missed. The guard that keeps the corpus positional is
`tests/evals/test_controls.py::test_the_corpus_speaks_the_SAME_esql_encoding_production_does`.

Usage:
  python defender/evals/oracle_golden/migrate_esql_encoding.py [--cases-dir DIR]

`--cases-dir` defaults to this script's own `cases/` directory; the flag lets the
migration run over a temporary copy of the tree (how it is tested).
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

GOLDEN_DIR = Path(__file__).resolve().parent

#: The four keys that make a dict an ES|QL payload (see `esql_payload` in
#: `scripts/adapters/elastic_adapter.py`). No other shape under `hidden/` carries all four.
ESQL_KEYS = ("query", "columns", "row_count", "values")

#: The JSON serializations that exactly reproduce every file under `hidden/`. A rewritten
#: file uses whichever reproduced its original bytes, so the diff stays data-only.
_SERIALIZATIONS: tuple[tuple[str, Any], ...] = (
    ("compact", lambda doc: json.dumps(doc)),
    ("indent2", lambda doc: json.dumps(doc, indent=2)),
    ("indent2+newline", lambda doc: json.dumps(doc, indent=2) + "\n"),
)


def is_esql_payload(obj: Any) -> bool:
    """True for a dict carrying ALL FOUR of `query`, `columns`, `row_count`, `values`."""
    return isinstance(obj, dict) and all(key in obj for key in ESQL_KEYS)


def to_columnar(payload: dict) -> dict:
    """`payload` with `values` re-encoded to positional rows (cell *i* named `columns[i]`).

    Key order and every other key are preserved. Already-positional or empty payloads come
    back unchanged, so the transform is idempotent. Each row is judged on its own, since a
    partially migrated payload can mix dict and list rows.

    Raises `ValueError` (message names "column") when:
      - a dict row's keys are not exactly `[c["name"] for c in payload["columns"]]`
        (re-zipping it by position would corrupt it);
      - a list row is not exactly `len(columns)` cells wide (truncated or corrupt);
      - a row is neither a dict nor a list.
    """
    rows = payload.get("values") or []
    if not rows:
        return payload

    names = [column["name"] for column in payload["columns"]]
    positional_rows = []
    changed = False
    for row in rows:
        if isinstance(row, dict):
            keys = list(row.keys())
            if keys != names:
                raise ValueError(
                    f"row's columns {keys!r} do not match payload columns {names!r}; "
                    "refusing to re-zip a row the columns don't describe")
            positional_rows.append([row[name] for name in names])
            changed = True
        elif isinstance(row, list):
            if len(row) != len(names):
                raise ValueError(
                    f"a positional row has {len(row)} cell(s) but payload names "
                    f"{len(names)} column(s) {names!r}; refusing a row the wrong width")
            positional_rows.append(row)
        else:
            raise ValueError(
                f"row is a {type(row).__name__}, not a dict or a positional list of "
                f"cells; not a column-shaped row for columns {names!r}")

    if not changed:
        return payload
    return {**payload, "values": positional_rows}


def to_dict_rows(payload: dict) -> dict:
    """The inverse of `to_columnar`: positional rows re-zipped to dicts in `columns` order.

    The migration round-trips every rewritten payload through this before touching disk.
    """
    rows = payload.get("values") or []
    if not rows or isinstance(rows[0], dict):
        return payload

    names = [column["name"] for column in payload["columns"]]
    dict_rows = [dict(zip(names, row, strict=True)) for row in rows]
    return {**payload, "values": dict_rows}


def _migrate_document(doc: Any) -> int:
    """Walk `doc` recursively, re-encoding every ES|QL payload found by shape, in place.

    Returns the number of payloads actually re-encoded.

    Verifies each change by re-zipping the new rows and comparing against the original rows
    (not against the transform's own output, which would miss a self-consistent bug). A
    mismatch raises `ValueError`, aborting the whole file.
    """
    rewritten = 0
    if isinstance(doc, dict):
        if is_esql_payload(doc):
            before_rows = doc.get("values") or []
            after_rows = to_columnar(doc).get("values") or []
            if after_rows != before_rows:
                reconstructed = to_dict_rows({**doc, "values": after_rows})["values"]
                for before_row, reconstructed_row in zip(before_rows, reconstructed,
                                                          strict=True):
                    if isinstance(before_row, dict) and reconstructed_row != before_row:
                        raise ValueError(
                            "lossy re-encode: re-zipping a migrated row did not reproduce "
                            f"its original dict row {before_row!r}")
                doc["values"] = after_rows
                rewritten += 1
        for value in doc.values():
            rewritten += _migrate_document(value)
    elif isinstance(doc, list):
        for item in doc:
            rewritten += _migrate_document(item)
    return rewritten


def _detect_serialization(doc: Any, original_text: str):
    """The rendering function (of `_SERIALIZATIONS`) that reproduces `original_text` from
    `doc`, or `None` if none of the three known forms does."""
    for _name, render in _SERIALIZATIONS:
        if render(doc) == original_text:
            return render
    return None


def migrate_file(path: Path) -> int:
    """Rewrite one JSON file's ES|QL payloads in place. Returns payloads rewritten.

    A zero-byte file (a recorded capture failure) is skipped unparsed. A file with nothing
    to migrate is never written. A migrated file keeps whichever `_SERIALIZATIONS` form
    reproduces its original bytes; if none does, raises `ValueError` (message names
    "serializ") and leaves the file untouched.
    """
    raw = path.read_bytes()
    if not raw.strip():
        return 0

    original_text = raw.decode("utf-8")
    original_doc = json.loads(original_text)

    migrated_doc = copy.deepcopy(original_doc)
    rewritten = _migrate_document(migrated_doc)
    if rewritten == 0:
        return 0

    render = _detect_serialization(original_doc, original_text)
    if render is None:
        raise ValueError(
            f"{path}: cannot reproduce this file's serialization from any known form; "
            "refusing to rewrite it (that would silently reformat it, not just migrate it)")

    path.write_text(render(migrated_doc), encoding="utf-8")  # lint-unguarded-tree-write: ok — local dev-run migration of the committed corpus, not a runtime/box writer
    return rewritten


def migrate_tree(cases_dir: Path) -> tuple[int, int]:
    """Migrate every `observed/` and `controls/` JSON file under `cases_dir`.

    Returns `(files_rewritten, payloads_rewritten)`. Idempotent: a second call over an
    already-migrated tree touches no file and returns `(0, 0)`.
    """
    paths = set(cases_dir.glob("*/hidden/observed/**/*.json"))  # lint-run-records: ok — an eval case's own file under the case tree, never a run record
    paths.update(cases_dir.glob("*/hidden/controls/**/*.json"))

    files_rewritten = 0
    payloads_rewritten = 0
    for path in sorted(paths):
        count = migrate_file(path)
        if count:
            files_rewritten += 1
            payloads_rewritten += count
    return files_rewritten, payloads_rewritten


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cases-dir", type=Path, default=GOLDEN_DIR / "cases",
        help="the oracle_golden cases/ directory to migrate (default: this script's own)")
    args = parser.parse_args(argv)

    files_rewritten, payloads_rewritten = migrate_tree(args.cases_dir)
    print(f"migrated {payloads_rewritten} ES|QL payload(s) across {files_rewritten} file(s) "
          f"under {args.cases_dir}")
    return 0


if __name__ == "__main__":  # lint-log-setup: ok — stdlib-only: run by path with no `defender` on the import path, so it cannot import the setup
    sys.exit(main())
