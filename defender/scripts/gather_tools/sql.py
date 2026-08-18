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

#: A missing `duckdb` is the ONE failure here that is not the caller's fault, and it must not
#: share `EXIT_INPUT_ERROR` with the three agent mistakes: `_record_shim_failure` files a failed
#: reduce as a lesson for the pitfalls curator, which writes prompt text into
#: `skills/{system}/execution.md`, and a deployment fault fails EVERY reduce — the queue would
#: fill with identical un-actionable records. 69 is sysexits' `EX_UNAVAILABLE`.
EXIT_NO_RUNTIME = 69

_MAX_OBJECT_SIZE = 1 << 30

#: The one spelling that binds `h` to the unnested STRUCT on the search-hits shape. Stated once
#: because two places quote it — `--help`'s epilog and the query-error hint — and a form that
#: drifts in one of them no longer runs.
_HITS_FROM = "FROM (SELECT unnest(hits) h FROM data)"


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


def _error_note(message: str) -> str:
    """The one clause that answers THIS error, or nothing.

    duckdb self-answers most of what lands here (`Candidate Entries: "user"`, `Did you mean
    "data"?`), and prose appended to a self-answering error buries the answer. So a clause is
    attached only where duckdb names the symptom and not the cause: the lateral join, whose
    `Candidate bindings` never says `h` bound the TABLE, and the unquoted `@`, whose parser
    error points at the character rather than at the quoting rule. Everything else gets the
    shape and the runnable skeleton alone.
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
    # Each branch punctuates itself: an idiom ENDING in a copyable query must not have a
    # sentence-terminating period appended to the query's last token.
    if "hits" in colset:
        idiom = (
            "search-hits shape — `unnest(hits)` yields a STRUCT. Copy this form:\n"
            f"    SELECT h.\"@timestamp\", h.message {_HITS_FROM} "
            "WHERE h.<field> = '<value>'"
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
            "`v[2]->>'$' = '<value>'`."
        )
    else:
        idiom = ("flat/array shape — the payload's keys ARE `data`'s columns; "
                 "`SELECT * FROM data`, no `unnest`.")
    return f"\n  hint: `data` has columns [{', '.join(cols)}]; {idiom}{_error_note(message)}"


def _disambiguate_columns(columns: list[str]) -> tuple[list[str], list[str]]:
    """Make the result-set column names unique, and say which ones moved.

    An unaliased projection of two ECS-nested fields (`h.host.name, h.agent.name`) collides on
    the leaf, and a row built by zipping into a dict keeps only the LAST of each colliding pair.
    Renaming rather than refusing keeps a legitimate `SELECT *` over a self-join working; the
    stderr note is what makes the narrowing loud, since a silently-dropped column is
    indistinguishable downstream from a field the payload never carried.
    """
    # Every LITERAL name is reserved up front, not as the walk reaches it: a projection can
    # spell its own `name_1` alias AFTER the collision that would generate one, and a generated
    # name that took it would hand the agent its alias holding the other column's value.
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
            print(f"defender-sql: query error: {exc}{_shape_hint(con, str(exc))}",
                  file=sys.stderr)
            return EXIT_QUERY_ERROR

        columns = [col[0] for col in cursor.description] if cursor.description else []
        columns, renamed = _disambiguate_columns(columns)
        rows = [_json_safe(dict(zip(columns, record, strict=True)))
                for record in cursor.fetchall()]
        json.dump(rows, sys.stdout, default=str, allow_nan=False)
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


if __name__ == "__main__":
    raise SystemExit(main())
