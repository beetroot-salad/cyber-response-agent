#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._io import json_safe, use_utf8_stdio

EXIT_OK = 0
EXIT_QUERY_ERROR = 1
EXIT_INPUT_ERROR = 2

#: A missing `duckdb` is a deployment fault, not the caller's mistake, so it gets its own exit
#: code (sysexits' `EX_UNAVAILABLE`): failed reduces are filed for the pitfalls curator, and
#: this one would fill the queue with identical un-actionable records.
EXIT_NO_RUNTIME = 69

_MAX_OBJECT_SIZE = 1 << 30

#: A format no text matches, handed to the loader as its date and timestamp format: the engine
#: otherwise guesses from the rows whether a field is a time, so the same field came back
#: converted in one payload and as text in the next (#1125). Text keeps the source's spelling;
#: the lead casts (`::TIMESTAMPTZ`) when it needs a time.
_NO_TIME_GUESS = "~text~%Y"

#: The form that binds `h` to the unnested struct on the search-hits shape, shared by
#: `--help`'s epilog and the query-error hint.
_HITS_FROM = "FROM (SELECT unnest(hits) h FROM data)"


def _top_level_columns(con) -> list[str]:
    return [row[0] for row in con.execute("DESCRIBE data").fetchall()]


def _is_esql(columns) -> bool:
    return "values" in columns and "columns" in columns


def _esql_rows_as_json(con) -> None:
    """Make every position of an ES|QL row JSON, as a row of mixed types already is.

    The engine types a row whose values share one type as that type, so `v[N]->>'$'` — the
    one idiom the lead is taught — failed on an all-text row and read an all-number one
    through a cast."""
    types = dict((row[0], row[1]) for row in con.execute("DESCRIBE data").fetchall())
    # A `values` with no rows is a flat list, and has no positions to retype.
    if not _is_esql(types) or not types["values"].endswith("[][]"):
        return
    con.execute(
        'CREATE OR REPLACE TABLE data AS SELECT * REPLACE '
        '(list_transform("values", r -> list_transform(r, x -> to_json(x))) AS "values") FROM data'
    )


def _error_note(message: str) -> str:
    """The clause that answers this error, or nothing.

    duckdb's own message usually answers itself, and extra prose would bury it. A clause is
    added only where duckdb names the symptom rather than the cause: the lateral-join binding
    of `h`, and the unquoted `@`.
    """
    low = message.lower()
    if "candidate bindings" in low and "unnest" in low:
        return (
            "\n  `AS h` on a lateral `unnest` binds `h` to the TABLE, whose single "
            "column is called `unnest` — so `h.<field>` cannot resolve. The subquery "
            "form above binds `h` to the struct itself."
        )
    if 'syntax error at or near "@"' in low:
        return (
            "\n  `@`-prefixed and dotted field names must be double-quoted: "
            "`h.\"@timestamp\"`, not `h.@timestamp`."
        )
    if "could not find key" in low:
        return "\n  `DESCRIBE data` names the struct's fields and their types."
    return ""


def _shape_hint(con, message: str) -> str:
    try:
        cols = _top_level_columns(con)
    except Exception:  # noqa: BLE001 — advisory only; a broken introspection must not mask the real error
        return ""
    colset = set(cols)
    # Each branch punctuates itself, so a copyable query does not get a trailing period.
    if "hits" in colset:
        idiom = (
            "search-hits shape — `unnest(hits)` yields a STRUCT. Copy this form:\n"
            f"    SELECT h.\"@timestamp\", h.message {_HITS_FROM} "
            "WHERE h.<field> = '<value>'"
        )
    elif _is_esql(colset):
        try:
            order = ", ".join(
                f"{i + 1}={c['name']}"
                for i, c in enumerate(con.execute("SELECT columns FROM data").fetchone()[0])
            )
        except Exception:  # noqa: BLE001
            order = "see `SELECT columns FROM data`"
        idiom = (
            "ES|QL shape — `unnest(values)` yields a POSITIONAL JSON array, NOT a struct "
            f"(`v.<field>` fails). Positions: {order}. Filter 1-based and unpack the JSON: "
            "`v[2]->>'$' = '<value>'`."
        )
    else:
        idiom = ("flat/array shape — the payload's keys ARE `data`'s columns; "
                 "`SELECT * FROM data`, no `unnest`.")
    return f"\n  hint: `data` has columns [{', '.join(cols)}]; {idiom}{_error_note(message)}"


def _disambiguate_columns(columns: list[str]) -> tuple[list[str], list[str]]:
    """Make result column names unique, and say which ones moved.

    Unaliased ECS fields (`h.host.name, h.agent.name`) collide on the leaf, and zipping into a
    dict would silently keep only the last. Renaming keeps `SELECT *` over a self-join working;
    the stderr note makes it visible.
    """
    # Reserve every literal name up front: a projection may spell its own `name_1` alias after
    # the collision that would generate one.
    taken = set(columns)
    seen: dict[str, int] = {}
    out: list[str] = []
    renamed: list[str] = []
    for col in columns:
        n = seen.get(col, 0)
        seen[col] = n + 1
        if n == 0:
            out.append(col)
            continue
        name = f"{col}_{n}"
        while name in taken:
            n += 1
            name = f"{col}_{n}"
        seen[col] = n + 1
        taken.add(name)
        out.append(name)
        renamed.append(f"{col} -> {name}")
    return out, renamed


def _collision_note(renamed: list[str]) -> str:
    return (
        f"defender-sql: note — duplicate output column name(s) renamed: {', '.join(renamed)}. "
        "Two projected fields share a leaf name (ECS nests them: `host.name`, `agent.name`). "
        "Alias them explicitly to control the key: "
        "SELECT h.host.name AS host_name, h.agent.name AS agent_name"
    )


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
        if os.environ.get("DEFENDER_BOX"):
            # Inside a box `duckdb` comes from the image (the mount is read-only), so the
            # remedy is rebuilding it.
            print(
                "defender-sql: duckdb is not installed in this box image "
                "(run `python3 defender/scripts/box_image.py build` to rebuild it).",
                file=sys.stderr,
            )
        else:
            print(
                "defender-sql: duckdb is not installed "
                "(cd defender && uv pip install --python .venv/bin/python -e '.[runtime]').",
                file=sys.stderr,
            )
        return EXIT_NO_RUNTIME

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
                f"read_json_auto(?, maximum_object_size={_MAX_OBJECT_SIZE}, "
                "dateformat=?, timestampformat=?)",
                [payload_path, _NO_TIME_GUESS, _NO_TIME_GUESS],
            )
            _esql_rows_as_json(con)
        except duckdb.Error as exc:
            print(f"defender-sql: stdin is not valid JSON or NDJSON: {exc}",
                  file=sys.stderr)
            return EXIT_INPUT_ERROR

        # The engine's zone otherwise follows the host's, and a day bucket would start at the
        # host's midnight.
        con.execute("SET TimeZone='UTC'")
        con.execute("SET enable_external_access=false")
        con.execute("SET lock_configuration=true")

        # The fetch is inside: handing a value to Python can fail in the engine too.
        try:
            cursor = con.execute(sql)
            records = cursor.fetchall()
        except duckdb.Error as exc:
            print(f"defender-sql: query error: {exc}{_shape_hint(con, str(exc))}",
                  file=sys.stderr)
            return EXIT_QUERY_ERROR

        columns = [col[0] for col in cursor.description] if cursor.description else []
        columns, renamed = _disambiguate_columns(columns)
        # `null` for a non-finite float and seconds for a duration: the model computes over
        # these rows, and a column that is number-or-null reads as one type where `"NaN"` or
        # `"1 day, 2:00:00"` would be a string among numbers. Zone-less timestamps are UTC: the
        # session's zone is UTC, so a zoned value cast to a plain one lands in UTC.
        rows = [json_safe(dict(zip(columns, record, strict=True)), non_finite="null",
                          naive_is_utc=True, durations_as_seconds=True)
                for record in records]
        json.dump(rows, sys.stdout, allow_nan=False)
        sys.stdout.write("\n")
        if renamed:
            print(_collision_note(renamed), file=sys.stderr)
        note = _truncation_note(con)
        if note:
            print(note, file=sys.stderr)
        return EXIT_OK
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def main() -> int:
    # The help and hints contain an em-dash and a lead's shell may be the `C` locale. Done
    # here, not at import, so in-process imports leave the host's streams alone.
    use_utf8_stdio()
    parser = argparse.ArgumentParser(
        prog="defender-sql",
        description="Sandboxed SQL aggregation over a JSON/NDJSON payload on stdin, "
                    "exposed as the table `data`. Tier-2 fallback for a source with "
                    "no native aggregation (see skills/connect/adapter.md).",
        epilog="the payload IS the table — there is no wrapper envelope to reach "
               "through. example: defender-<system> query '<filter>' | defender-sql "
               f"\"SELECT h.user, count(*) c {_HITS_FROM} GROUP BY 1 ORDER BY c DESC\"",
    )
    parser.add_argument(
        "sql",
        help="A read-only SQL query over the `data` table (the parsed stdin payload).",
    )
    args = parser.parse_args()
    return _run(args.sql)


if __name__ == "__main__":  # lint-log-setup: ok — a model tool — its stderr is read back by the model as plain text
    raise SystemExit(main())
