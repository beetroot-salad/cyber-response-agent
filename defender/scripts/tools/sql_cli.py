#!/usr/bin/env python3
"""defender-sql — sandboxed SQL aggregation over a JSON payload on stdin.

The gather subagent pipes a filter-only adapter's `--raw` output through
this tool to aggregate it server-side-style instead of reducing the
payload by hand:

    defender-{system} query '<native filter>' --raw | defender-sql \\
        "SELECT h.user AS user, count(*) c \\
         FROM (SELECT unnest(result.hits) h FROM data) \\
         GROUP BY user ORDER BY c DESC"

It is the **tier-2 fallback** for a source with no native aggregating
query language (see `skills/connect/cli-adapter.md` -> "Prefer native
aggregation"). A source that can aggregate in its own language
(elastic -> ES|QL) never needs it — that aggregation runs in the source.

The stdin JSON is exposed as a table named `data`, parsed with DuckDB's
`read_json_auto` type inference (structs and lists preserved), so SQL
written against it reads the same as `FROM read_json_auto('/dev/stdin')`.
Input is one JSON value (e.g. the `--raw` envelope `{system, endpoint,
args, result}`) or NDJSON / a JSON array (one value per row). Output is a
JSON array of row objects on stdout.

Sandbox: the payload is materialized into an in-memory table, then DuckDB
is sealed — `enable_external_access=false` + `lock_configuration=true` —
*before* the caller's SQL runs. So that SQL cannot read or write files,
reach the network, load an extension, ATTACH another database, or
re-enable any of it. This is what lets the tool be auto-approved for the
gather subagent, which handles untrusted (injection-tagged) source data:
the permission layer matches on the `defender-sql` token, and the sandbox
— not the permission layer — is what bounds the SQL.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile

EXIT_OK = 0           # success (an empty result set is still 0)
EXIT_QUERY_ERROR = 1  # the SQL was rejected by DuckDB
EXIT_INPUT_ERROR = 2  # no stdin, unparseable payload, or duckdb missing

# read_json_auto's default per-object cap is small; a single `--raw` envelope
# can be larger, so lift it. 1 GiB is a generous ceiling, not a target.
_MAX_OBJECT_SIZE = 1 << 30


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

    raw = sys.stdin.read()
    if not raw.strip():
        print("defender-sql: no input on stdin (pipe an adapter's --raw output in).",
              file=sys.stderr)
        return EXIT_INPUT_ERROR

    scratch = tempfile.mkdtemp(prefix="defender-sql-")
    try:
        payload_path = os.path.join(scratch, "data.json")
        with open(payload_path, "w") as handle:
            handle.write(raw)

        con = duckdb.connect(":memory:")
        # Materialize the payload while file access is still on. The path is
        # shim-controlled (mkdtemp) and no caller SQL has run yet, so this read
        # is safe; the caller never sees the path.
        try:
            con.execute(
                f"CREATE TABLE data AS "
                f"SELECT * FROM read_json_auto('{payload_path}', "
                f"maximum_object_size={_MAX_OBJECT_SIZE})"
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
        rows = [dict(zip(columns, record)) for record in cursor.fetchall()]
        json.dump(rows, sys.stdout, default=str)
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
        epilog="example: defender-elastic query '<filter>' --raw | defender-sql "
               "\"SELECT h.user, count(*) c "
               "FROM (SELECT unnest(result.hits) h FROM data) GROUP BY 1 ORDER BY c DESC\"",
    )
    parser.add_argument(
        "sql",
        help="A read-only SQL query over the `data` table (the parsed stdin payload).",
    )
    args = parser.parse_args()
    return _run(args.sql)


if __name__ == "__main__":
    raise SystemExit(main())
