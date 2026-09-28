#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
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

#: The form that binds `h` to the unnested struct on the search-hits shape, shared by
#: `--help`'s epilog and the query-error hint.
_HITS_FROM = "FROM (SELECT unnest(hits) h FROM data)"


def _top_level_columns(con) -> list[str]:
    return [row[0] for row in con.execute("DESCRIBE data").fetchall()]


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


#: What an arrow's JSON source may be, as duckdb's parse names it: a column or struct field, a
#: position (`v[2]`), a function call, a cast, a constant, a subquery, a CASE or COALESCE, or
#: another arrow (`->` parses as a LAMBDA). An operator expression is not on it — see `_arrow_refusal`.
_JSON_SOURCE_CLASSES = frozenset({"COLUMN_REF", "CONSTANT", "CAST", "SUBQUERY", "CASE", "LAMBDA"})
_JSON_SOURCE_OPERATORS = frozenset({"ARRAY_EXTRACT", "OPERATOR_COALESCE"})
_NAMED_FUNCTION = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

_MISBOUND = (
    "defender-sql: query error: `->>` binds more loosely than the operators before it (`=`, "
    "`<>`, AND, OR, NOT, `||` …), so here it takes that whole expression as its JSON — which "
    "errors on some rows and answers a silent, wrong count on others. Parenthesise every `->>`: "
    "`(v[1]->>'$') = '<value>' AND (v[2]->>'$') = '<value>'`. (An expression you mean as the "
    "JSON goes in `CAST(<expression> AS JSON)->>'<path>'`.)"
)
_UNCHECKABLE = (
    "defender-sql: query error: a query with `->>` must be a single SELECT (or several), which is "
    "what the tool can check for a misbound arrow; rewrite it without CREATE, PIVOT or the like."
)


def _json_source(node: dict) -> bool:
    cls = node.get("class")
    if cls == "FUNCTION":
        name = node.get("function_name", "")
        return name == "->>" or bool(_NAMED_FUNCTION.fullmatch(name))
    if cls == "OPERATOR":
        return node.get("type") in _JSON_SOURCE_OPERATORS
    return cls in _JSON_SOURCE_CLASSES


def _arrow_refusal(con, sql: str) -> str | None:
    """Why the query must not run, if one of its `->>` arrows is misbound; else None.

    duckdb binds `->>` more loosely than the operators written before it, so
    `v[1]->>'$' = 'x' AND v[2]->>'$' = 'y'` parses as `((v[1]->>'$') = 'x' AND v[2]) ->> '$' = 'y'`
    and `'x' = v[1]->>'$'` as `('x' = v[1]) ->> '$'`. Depending on the values that errors or
    answers a silent, wrong count — the fake absence a lead cannot tell from a real one. Each
    arrow's source is read off duckdb's own parse and must be something that can hold JSON. The
    parse keeps no parentheses, so a deliberate `(a || b)->>'$'` is refused with it; the refusal
    names the CAST that says so. Only SELECT statements have a parse to read, so any other
    statement holding an arrow is refused too.
    """
    if "->>" not in sql:
        return None
    try:
        tree = json.loads(con.execute("SELECT json_serialize_sql(?)", [sql]).fetchone()[0])
    except Exception:  # noqa: BLE001 — advisory only; the query itself reports what is wrong with it
        return None
    if tree.get("error"):
        # Only a statement duckdb parsed but will not describe is unchecked; a syntax error is
        # left to the query, whose own message names the spot.
        return _UNCHECKABLE if "Only SELECT" in tree.get("error_message", "") else None
    stack = [tree]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if (node.get("class") == "FUNCTION" and node.get("function_name") == "->>"
                    and not _json_source((node.get("children") or [{}])[0])):
                return _MISBOUND
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return None


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
            f"(`v.<field>` fails). Positions: {order}. Filter 1-based and unpack the JSON: "
            "`(v[2]->>'$') = '<value>'`."
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


def _no_runtime(module: str) -> int:
    if os.environ.get("DEFENDER_BOX"):
        # Inside a box the runtime comes from the image (the mount is read-only), so the
        # remedy is rebuilding it.
        print(
            f"defender-sql: {module} is not installed in this box image "
            "(run `python3 defender/scripts/box_image.py build` to rebuild it).",
            file=sys.stderr,
        )
    else:
        print(
            f"defender-sql: {module} is not installed "
            "(cd defender && uv pip install --python .venv/bin/python -e '.[runtime]').",
            file=sys.stderr,
        )
    return EXIT_NO_RUNTIME


#: duckdb imports some modules only to hand a value to Python (`pytz` for a zoned timestamp),
#: so one missing from the install surfaces as an engine error on the query that returns such a
#: value — a deployment fault, not the lead's query.
_MISSING_MODULE = re.compile(r"Required module '([^']+)' failed to import")


def _run(sql: str) -> int:
    try:
        import duckdb
    except ImportError:
        return _no_runtime("duckdb")

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

        # A zoned value crosses into Python in the session's zone, which otherwise follows the
        # host's: a plain timestamp cast to a zoned one, or a day bucket, would shift by the host's
        # offset, and an empty `TZ` names a zone pytz cannot resolve.
        con.execute("SET TimeZone='UTC'")
        con.execute("SET enable_external_access=false")
        con.execute("SET lock_configuration=true")

        if refusal := _arrow_refusal(con, sql):
            print(f"{refusal}{_shape_hint(con, refusal)}", file=sys.stderr)
            return EXIT_QUERY_ERROR

        # The fetch is inside: handing a value to Python can fail in the engine too (#1126).
        try:
            cursor = con.execute(sql)
            records = cursor.fetchall()
        except duckdb.Error as exc:
            if missing := _MISSING_MODULE.search(str(exc)):
                return _no_runtime(missing.group(1))
            print(f"defender-sql: query error: {exc}{_shape_hint(con, str(exc))}",
                  file=sys.stderr)
            return EXIT_QUERY_ERROR

        columns = [col[0] for col in cursor.description] if cursor.description else []
        columns, renamed = _disambiguate_columns(columns)
        # `null` for a non-finite float: the model computes over these rows, and a column that
        # is number-or-null reads as one type where `"NaN"` would be a string among numbers.
        # Zone-less timestamps are UTC: the engine converts an offset to UTC when it loads one,
        # and the session's zone is UTC.
        rows = [json_safe(dict(zip(columns, record, strict=True)), non_finite="null",
                          naive_is_utc=True)
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
