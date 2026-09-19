#!/usr/bin/env python3
"""Re-encode the golden corpus's ES|QL payloads to production's positional shape (#1054).

#842 moved the `esql` verb (and `controls.py`, through the same `esql_payload` shaper) to
emit `values` as the wire sends them — rows are bare arrays, cell `i` bound to
`columns[i]` — but the committed corpus under `evals/oracle_golden/cases/*/hidden/` was
never migrated: every ES|QL payload on disk still holds the pre-#842 dict-row form. A
`controls.py` rerun (which `known_defects.yaml`'s own `repair:` notes tell someone to do)
only regenerates `hidden/controls/`, so the observed half would stay dict-row while the
controls half came back positional — one judge prompt, two encodings of the same data.

This script closes that gap in one pass: every ES|QL payload anywhere under
`cases/*/hidden/{observed,controls}/**/*.json` is re-encoded from dict rows to positional
rows, losslessly (re-zipping by `columns[].name` reproduces the original exactly) and
minimally (a file keeps its own JSON serialization; a file with nothing to migrate is not
touched at all). It is idempotent — a second run over an already-migrated tree rewrites
nothing — which is also why a future `controls.py` rerun cannot re-split the corpus: its
writer already goes through `esql_payload`, so it only ever writes what this script also
writes.

A payload is found by SHAPE (any dict carrying all four of `query`, `columns`, `row_count`,
`values`), never by an enumerated list of positions. An enumerated sweep is exactly the bug
that produced #1054: #842 moved the shape, and nothing that only knew a fixed set of
positions noticed a payload sitting somewhere else (`attack_contribution.payload`, or any
future position). The guard that keeps this true going forward lives beside the shaper it
protects: `tests/evals/test_controls.py::test_the_corpus_speaks_the_SAME_esql_encoding_production_does`.

Usage:
  python defender/evals/oracle_golden/migrate_esql_encoding.py [--cases-dir DIR]

`--cases-dir` defaults to this script's own `cases/` directory, so the committed,
replayable command is the bare invocation; the flag exists so the migration can also be
driven over a temporary copy of the tree (how it is tested).
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

GOLDEN_DIR = Path(__file__).resolve().parent

#: The four keys that make a dict an ES|QL payload — see `esql_payload` in
#: `scripts/adapters/elastic_adapter.py`. No non-ES|QL shape under `hidden/` carries all
#: four (a lookup/state stub has neither `columns` nor `values`), so this classifies
#: cleanly with no false positives on the corpus as it exists today.
ESQL_KEYS = ("query", "columns", "row_count", "values")

#: The three JSON serializations every file under `hidden/` is reproduced by exactly
#: (census: 526 compact, 342 indent=2+newline, 9 indent=2, 80 zero-byte, 0 unmatched). A
#: rewritten file is written back through whichever of these reproduced its ORIGINAL bytes,
#: so a 482-file data migration stays a data migration and not a 957-file whitespace diff.
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

    Every other key keeps its value, and the returned dict keeps `payload`'s own key
    order — anything else would move bytes outside `values`, which is exactly the diff
    noise the rewrite is supposed to avoid. A payload whose rows are already lists, or
    whose `values` is empty, comes back equal to its input (this is what makes the
    transform a fixed point on its own output, and the migration idempotent).

    Raises `ValueError` (message names "column") when a row's key list is not exactly
    `[c["name"] for c in payload["columns"]]` — reordered, missing a column, or carrying
    one the columns don't name. Re-zipping such a row by position would silently corrupt
    it, so it is refused rather than guessed at.
    """
    rows = payload.get("values") or []
    if not rows or not isinstance(rows[0], dict):
        return payload

    names = [column["name"] for column in payload["columns"]]
    positional_rows = []
    for row in rows:
        keys = list(row.keys())
        if keys != names:
            raise ValueError(
                f"row's columns {keys!r} do not match payload columns {names!r}; "
                "refusing to re-zip a row the columns don't describe")
        positional_rows.append([row[name] for name in names])

    return {**payload, "values": positional_rows}


def to_dict_rows(payload: dict) -> dict:
    """The inverse of `to_columnar`: positional rows re-zipped to dicts in `columns` order.

    This is the round-trip half of losslessness, and the migration runs it on every
    payload it rewrites to confirm nothing was lost before touching disk.
    """
    rows = payload.get("values") or []
    if not rows or isinstance(rows[0], dict):
        return payload

    names = [column["name"] for column in payload["columns"]]
    dict_rows = [dict(zip(names, row, strict=True)) for row in rows]
    return {**payload, "values": dict_rows}


def _migrate_document(doc: Any) -> int:
    """Walk `doc` recursively, re-encoding every ES|QL payload found by shape, in place.

    Recursive and shape-driven rather than an enumerated list of positions: today's
    payloads sit at three known positions (the observed root, `controls[i].payload`,
    `attack_contribution.payload`), and a sweep written against that list would miss a
    fourth the day one appears — which is the day the corpus splits again unnoticed.

    Returns the number of payloads actually re-encoded (payloads that were already
    positional, or empty, don't count — nothing about them changed).
    """
    rewritten = 0
    if isinstance(doc, dict):
        if is_esql_payload(doc):
            rows = doc.get("values") or []
            if rows and isinstance(rows[0], dict):
                columnar = to_columnar(doc)
                # Confirm losslessness before committing the change to this document.
                assert to_dict_rows(columnar)["values"] == doc["values"]
                doc["values"] = columnar["values"]
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

    A zero-byte file is skipped (a recorded capture failure, not an empty result — see
    `README.md`) and returns 0 without being parsed. A file with nothing to migrate is not
    written at all: not re-serialized, not touched, byte-identical, so a file whose format
    this script cannot reproduce never fails a run that had no business touching it.

    A file that DOES have something to migrate keeps its own serialization — whichever of
    `json.dumps(doc)` / `json.dumps(doc, indent=2)` / `json.dumps(doc, indent=2) + "\\n"`
    reproduces its ORIGINAL bytes. If none does, raises `ValueError` (message names
    "serializ") and leaves the file untouched rather than silently reformatting it.
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

    path.write_text(render(migrated_doc), encoding="utf-8")
    return rewritten


def migrate_tree(cases_dir: Path) -> tuple[int, int]:
    """Migrate every `observed/` and `controls/` JSON file under `cases_dir`.

    Returns `(files_rewritten, payloads_rewritten)`. Idempotent: a second call over an
    already-migrated tree touches no file and returns `(0, 0)`.
    """
    paths = set(cases_dir.glob("*/hidden/observed/**/*.json"))
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


if __name__ == "__main__":
    sys.exit(main())
