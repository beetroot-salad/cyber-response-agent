#!/usr/bin/env python3
"""defender-sql — sandboxed SQL aggregation over a JSON payload on stdin.

Two consumers, both piping a payload in rather than naming a file (this
tool NEVER opens one):

  * **gather**, live — the tier-2 fallback for a source with no native
    aggregating query language (see `skills/connect/cli-adapter.md` ->
    "Prefer native aggregation"). A source that aggregates in its own
    language (e.g. ES|QL) never needs it; that aggregation runs in the
    source.

        defender-{system} query '<native filter>' | defender-sql \\
            "SELECT h.user AS user, count(*) c \\
             FROM (SELECT unnest(hits) h FROM data) \\
             GROUP BY user ORDER BY c DESC"

  * **the judge**, at rest — aggregating a captured payload to ground or
    refute a projection, its `cat` operand path-gated to its read roots:

        cat {run}/gather_raw/{lead}/{seq}.json | defender-sql \\
            "SELECT count(*) FROM (SELECT unnest(hits) h FROM data) \\
             WHERE h.user = 'alice'"

The stdin JSON is exposed as a table named `data`, parsed with DuckDB's
`read_json_auto` type inference (structs and lists preserved), so SQL
written against it reads the same as `FROM read_json_auto('/dev/stdin')`.
The payload IS the table: a top-level **object** yields one row whose
columns are its keys; a top-level **array** (or NDJSON) yields one row per
element. There is no wrapper envelope to reach through — an adapter's
stdout is the payload verbatim. Output is a JSON array of row objects on
stdout.

`DESCRIBE data` runs against every shape and names the columns the payload
actually has; projecting one it lacks is a Binder Error, not an empty
result. Shapes an onboarded adapter emits today, and the idiom for each:

    {index, total, returned, truncated, hits}  ->  unnest(hits) -> a STRUCT;
                                                   filter on h.<field>
    {columns, row_count, values}   (ES|QL)     ->  unnest(values) -> a
                                                   POSITIONAL JSON[] , not a
                                                   struct: `SELECT columns FROM
                                                   data` for the field order,
                                                   then 1-based `v[2]->>'$'`
    a flat object (cmdb/identity/...)          ->  SELECT * FROM data
    a bare array of docs                       ->  SELECT ... FROM data

`truncated`/`total` are load-bearing for absence checks on the search-hits
shape (the only one carrying them): `hits` holds only the first `returned`
rows, so "not in `hits`" means "absent" only when `truncated` is false. An
empty payload is an input error (exit 2), never an empty result set —
absence must be read off a query, not off silence.

Sandbox: the payload is materialized into an in-memory table, then DuckDB
is sealed — `enable_external_access=false` + `lock_configuration=true` —
*before* the caller's SQL runs. So that SQL cannot read or write files,
reach the network, load an extension, ATTACH another database, or
re-enable any of it. This is what lets the tool be auto-approved for
agents handling untrusted (injection-tagged) source data: the permission
layer matches on the `defender-sql` token, and the sandbox — not the
permission layer — is what bounds the SQL.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import sys
import tempfile

EXIT_OK = 0           # success (an empty result set is still 0)
EXIT_QUERY_ERROR = 1  # the SQL was rejected by DuckDB
EXIT_INPUT_ERROR = 2  # no stdin, unparseable payload, or duckdb missing

# read_json_auto's default per-object cap is small; a single adapter payload
# can be larger, so lift it. 1 GiB is a generous ceiling, not a target.
_MAX_OBJECT_SIZE = 1 << 30


def _json_safe(value):
    """Map non-finite floats (NaN/±Infinity — e.g. a divide-by-zero ratio or a
    single-row stddev) to null, recursing through DuckDB structs/lists. Those
    are not valid JSON (RFC 8259); without this a strict downstream parser (JS
    `JSON.parse`, Go) rejects the whole output. Mirrors `JSON.stringify`."""
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value


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

    # Read as bytes, not text: the payload is untrusted source data and may
    # carry non-UTF-8 (or, under a C/POSIX locale, any non-ASCII) bytes. A
    # text-mode read+write would raise an uncaught UnicodeError instead of a
    # clean exit; let DuckDB's read_json_auto do the decoding and report
    # malformed input as a normal EXIT_INPUT_ERROR below.
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
        # Materialize the payload while file access is still on; no caller SQL
        # has run yet, so this read is safe and the caller never sees the path.
        # Bind the path as a parameter rather than interpolate it — mkdtemp
        # honors $TMPDIR, so a TMPDIR containing a quote would otherwise break
        # the string literal (every call fails) and run the broken-out text as
        # SQL before the seal below. `maximum_object_size` is a constant int.
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

        # Seal the connection before the caller's SQL runs. lock_configuration
        # makes the seal one-way — the caller's SQL can't SET it back.
        con.execute("SET enable_external_access=false")
        con.execute("SET lock_configuration=true")

        try:
            cursor = con.execute(sql)
        except duckdb.Error as exc:
            print(f"defender-sql: query error: {exc}", file=sys.stderr)
            return EXIT_QUERY_ERROR

        columns = [col[0] for col in cursor.description] if cursor.description else []
        rows = [_json_safe(dict(zip(columns, record, strict=True)))
                for record in cursor.fetchall()]
        # allow_nan=False guarantees strict JSON; _json_safe has already mapped
        # any non-finite float to null, so this never actually rejects a row.
        json.dump(rows, sys.stdout, default=str, allow_nan=False)
        sys.stdout.write("\n")
        return EXIT_OK
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="defender-sql",
        description="Sandboxed SQL aggregation over a JSON/NDJSON payload on stdin, "
                    "exposed as the table `data`. Tier-2 fallback for a source with "
                    "no native aggregation (see skills/connect/cli-adapter.md).",
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
