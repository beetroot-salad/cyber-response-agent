#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import sys
import tempfile

EXIT_OK = 0
EXIT_QUERY_ERROR = 1
EXIT_INPUT_ERROR = 2

_MAX_OBJECT_SIZE = 1 << 30


def _json_safe(value):
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value




def _top_level_columns(con) -> list[str]:
    return [row[0] for row in con.execute("DESCRIBE data").fetchall()]


def _shape_hint(con) -> str:
    try:
        cols = _top_level_columns(con)
    except Exception:  # noqa: BLE001 — advisory only; a broken introspection must not mask the real error
        return ""
    colset = set(cols)
    if "hits" in colset:
        idiom = (
            "search-hits shape — `unnest(hits)` yields a STRUCT, filter on `h.<field>`; "
            "the field names live inside it (`SELECT unnest(hits) h FROM data LIMIT 1`)"
        )
    elif "values" in colset and "columns" in colset:
        try:
            order = ", ".join(
                f"{i + 1}={c['name']}"
                for i, c in enumerate(con.execute("SELECT columns FROM data").fetchone()[0])
            )
        except Exception:  # noqa: BLE001
            order = "see `SELECT columns FROM data`"
        idiom = (
            "ES|QL shape — `unnest(values)` yields a POSITIONAL JSON array, NOT a struct "
            f"(`v.<field>` fails). Positions: {order}. Filter 1-based and unwrap the JSON: "
            "`v[2]->>'$' = '<value>'`"
        )
    else:
        idiom = "flat/array shape — the payload's keys ARE `data`'s columns; `SELECT * FROM data`, no `unnest`"
    return f"\n  hint: `data` has columns [{', '.join(cols)}]; {idiom}."


def _truncation_note(con) -> str:
    try:
        if "truncated" not in _top_level_columns(con):
            return ""
        if con.execute("SELECT 1 FROM data WHERE truncated LIMIT 1").fetchone() is None:
            return ""
    except Exception:  # noqa: BLE001
        return ""
    return (
        "defender-sql: note — this payload is TRUNCATED: `hits` holds only the first "
        "`returned` of `total` matching rows. A 0 or a miss here means 'not in the first "
        "rows', NOT 'absent' — a truncated payload cannot support an absence refutation."
    )


def _run(sql: str) -> int:
    try:
        import duckdb
    except ImportError:
        print(
            "defender-sql: duckdb is not installed "
            "(cd defender && uv pip install --python .venv/bin/python -e '.[runtime]').",
            file=sys.stderr,
        )
        return EXIT_INPUT_ERROR

    raw = sys.stdin.buffer.read()
    if not raw.strip():
        print(
            "defender-sql: no input on stdin — the payload is empty. This is NOT an "
            "empty result set: the query that produced it recorded no observation at "
            "all, so nothing here supports a claim about what is present or absent.",
            file=sys.stderr,
        )
        return EXIT_INPUT_ERROR

    scratch = tempfile.mkdtemp(prefix="defender-sql-")
    try:
        payload_path = os.path.join(scratch, "data.json")
        with open(payload_path, "wb") as handle:
            handle.write(raw)

        con = duckdb.connect(":memory:")
        try:
            con.execute(
                "CREATE TABLE data AS SELECT * FROM "
                f"read_json_auto(?, maximum_object_size={_MAX_OBJECT_SIZE})",
                [payload_path],
            )
        except duckdb.Error as exc:
            print(f"defender-sql: stdin is not valid JSON or NDJSON: {exc}",
                  file=sys.stderr)
            return EXIT_INPUT_ERROR

        con.execute("SET enable_external_access=false")
        con.execute("SET lock_configuration=true")

        try:
            cursor = con.execute(sql)
        except duckdb.Error as exc:
            print(f"defender-sql: query error: {exc}{_shape_hint(con)}", file=sys.stderr)
            return EXIT_QUERY_ERROR

        columns = [col[0] for col in cursor.description] if cursor.description else []
        rows = [_json_safe(dict(zip(columns, record, strict=True)))
                for record in cursor.fetchall()]
        json.dump(rows, sys.stdout, default=str, allow_nan=False)
        sys.stdout.write("\n")
        note = _truncation_note(con)
        if note:
            print(note, file=sys.stderr)
        return EXIT_OK
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="defender-sql",
        description="Sandboxed SQL aggregation over a JSON/NDJSON payload on stdin, "
                    "exposed as the table `data`. Tier-2 fallback for a source with "
                    "no native aggregation (see skills/connect/adapter.md).",
        epilog="the payload IS the table — there is no wrapper envelope to reach "
               "through. example: defender-<system> query '<filter>' | defender-sql "
               "\"SELECT h.user, count(*) c "
               "FROM (SELECT unnest(hits) h FROM data) GROUP BY 1 ORDER BY c DESC\"",
    )
    parser.add_argument(
        "sql",
        help="A read-only SQL query over the `data` table (the parsed stdin payload).",
    )
    args = parser.parse_args()
    return _run(args.sql)


if __name__ == "__main__":
    raise SystemExit(main())
