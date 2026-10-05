from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import unicodedata

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


def _describe(con) -> list[tuple[str, str]]:
    """`data`'s columns as `(name, type)`, or none when the engine will not say: every caller
    is advisory, and a broken introspection must not mask the answer or the real error."""
    try:
        return [(row[0], row[1]) for row in con.execute("DESCRIBE data").fetchall()]
    except Exception:  # noqa: BLE001
        return []


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
    "`(col->>'$') = '<value>' AND (other->>'$') = '<value>'`. (An expression you mean as the "
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


def _shape_hint(described: list[tuple[str, str]], message: str,
                declaration: str | None) -> str:
    """The query-error hint for an UNDECLARED payload: its columns, and the idiom for its shape.
    `declaration` is the `--rows … --names …` for a payload of positional rows, else None."""
    if not described:
        return ""
    cols = [name for name, _ in described]
    # Each branch punctuates itself, so a copyable query does not get a trailing period.
    if declaration is not None:
        idiom = ("positional rows — undeclared, the whole payload is ONE row of `data`. "
                 f"Declare them: {declaration}")
    elif "hits" in cols:
        idiom = (
            "search-hits shape — `unnest(hits)` yields a STRUCT. Copy this form:\n"
            f"    SELECT h.\"@timestamp\", h.message {_HITS_FROM} "
            "WHERE h.<field> = '<value>'"
        )
    else:
        idiom = ("flat/array shape — the payload's keys ARE `data`'s columns; "
                 "`SELECT * FROM data`, no `unnest`.")
    return f"\n  hint: `data` has columns [{', '.join(cols)}]; {idiom}{_error_note(message)}"


def _declared_hint(described: list[tuple[str, str]], message: str) -> str:
    """The query-error hint over a declared table: its columns and types, plus the clause for
    the two errors a declared column's type causes — a list compared as a scalar, and a JSON
    column compared as text."""
    if not described:
        return ""
    cols = ", ".join(f"{_quote_ident(name)} {typ}" for name, typ in described)
    low = message.lower()
    clause = ""
    if "[]" in message and ("conversion" in low or "cast" in low):
        clause = ("\n  A LIST column holds lists, not values: filter with "
                  "`list_contains(<col>, '<value>')`, or `unnest` the column in a subquery to get "
                  "one row per element.")
    elif "malformed json" in low:
        clause = ("\n  A JSON column holds JSON, not text: compare `(<col>->>'$')`, and cast it "
                  "to compare a number: `TRY_CAST((<col>->>'$') AS DOUBLE)`.")
    return (f"\n  hint: `data` has the declared columns [{cols}]; double-quote a name that "
            f"holds `.`, `@` or other punctuation.{clause}")


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


def _is_truncated(value: object) -> bool:
    """Whether a payload's `truncated` field says its rows are not all that matched — the one
    reading of that field, for the undeclared payload and the declared one alike."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1"}
    return False


def _truncation_note(con, described: list[tuple[str, str]]) -> str:
    if "truncated" not in (name for name, _ in described):
        return ""
    try:
        values = [row[0] for row in con.execute("SELECT truncated FROM data").fetchall()]
    except Exception:  # noqa: BLE001
        return ""
    if not any(_is_truncated(value) for value in values):
        return ""
    return (
        "defender-sql: note — this payload is TRUNCATED: `hits` holds only the first "
        "`returned` of `total` matching rows. A 0 or a miss here means 'not in the first "
        "rows', NOT 'absent' — a truncated payload cannot support an absence refutation."
    )


def _declared_truncation_note(truncated: bool) -> str:
    """The flagged path's truncation note. Under the flag the envelope's own fields are not in
    `data`, so the load reads `truncated` off the parsed envelope and hands it here."""
    if not truncated:
        return ""
    return (
        "defender-sql: note — the payload declares `truncated`: these rows are not all that "
        "matched. A 0 or a miss here means 'not in these rows', NOT 'absent' — a truncated "
        "payload cannot support an absence refutation."
    )


def _list_column_note(described: list[tuple[str, str]]) -> str:
    """O4: a list column never answers silently as if it held scalars."""
    lists = [name for name, typ in described if typ.endswith("[]")]
    if not lists:
        return ""
    named = ", ".join(_quote_ident(name) for name in lists)
    first = _quote_ident(lists[0])
    return (
        f"defender-sql: note — list column(s) {named}: each cell is a LIST, not a value. "
        f"Filter with `list_contains({first}, '<value>')`; to count or group its elements, "
        "`unnest` it in a subquery first. `GROUP BY` or `count(DISTINCT …)` on the column "
        "itself groups whole lists, not their elements."
    )


def _json_column_note(described: list[tuple[str, str]]) -> str:
    """A JSON column (cells of mixed kinds) never compares silently as text: `->>` unpacks it
    to TEXT, where '9' sorts above '412'."""
    jsons = [name for name, typ in described if typ == "JSON"]
    if not jsons:
        return ""
    named = ", ".join(_quote_ident(name) for name in jsons)
    first = _quote_ident(jsons[0])
    return (
        f"defender-sql: note — JSON column(s) {named}: the cells are not all one plain kind, "
        f"so each is JSON, not a typed value. `({first}->>'$')` gives TEXT, which compares and sorts as text; "
        f"cast it to compare, sort or sum a number: `TRY_CAST(({first}->>'$') AS DOUBLE)` "
        "(NULL where the cell is not a number)."
    )


#: A payload key echoed into a copyable command only when it is this plain — and not led by a
#: `-`, which the command line would read as a flag.
_ECHOABLE_KEY = re.compile(r"[A-Za-z0-9_@][A-Za-z0-9_@-]*")


def _single_document(raw: bytes) -> object:
    """The payload parsed as ONE JSON document, or None when it is not one (NDJSON, not JSON)."""
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        return None


def _positional_declaration(payload: object) -> str | None:
    """O6: the `--rows … --names …` that declares an UNDECLARED payload's positional rows, or
    None when it holds none.

    Read off the parsed payload, never off the engine's inferred types (which call an empty
    `values` something other than a list of lists) and never off a key's name: ONE top-level
    object, one of whose keys holds a list of lists. An empty list counts only beside a list
    of names, the only thing that says it is rows. Unflagged, such a payload is one row, so
    `count(*)` answers 1 without an error; this is what says so.
    """
    if not isinstance(payload, dict):
        return None
    for rows_key, rows in payload.items():
        if not (isinstance(rows, list) and all(isinstance(row, list) for row in rows)):
            continue
        width = len(rows[0]) if rows else None
        names_key = next(
            (key for key, value in payload.items()
             if key != rows_key and (names := _name_list(value)) is not None
             and (width is None or len(names) == width)),
            None,
        )
        if not rows and names_key is None:
            continue
        rows_arg = rows_key if _ECHOABLE_KEY.fullmatch(rows_key) else "<key>"
        names_arg = (names_key if names_key is not None and _ECHOABLE_KEY.fullmatch(names_key)
                     else "<names-key>")
        return f"--rows {rows_arg} --names {names_arg}"
    return None


def _positional_rows_note(declaration: str | None) -> str:
    if declaration is None:
        return ""
    # The declaration ends the note, so a copy of it carries no trailing punctuation.
    return (
        "defender-sql: note — this payload holds positional rows. Undeclared, the whole "
        "payload is ONE row of `data`, so `count(*)` answers 1. Declare them: "
        f"{declaration}"
    )


class _Refused(Exception):
    """A defect in the `--rows`/`--names` declaration or its payload, with its exit code."""

    def __init__(self, message: str, code: int = EXIT_QUERY_ERROR) -> None:
        super().__init__(message)
        self.code = code


_PATH = re.compile(r"[^.\[\]]+(?:\[\d+\])?(?:\.[^.\[\]]+(?:\[\d+\])?)*")
_PATH_STEP = re.compile(r"([^.\[\]]+)(?:\[(\d+)\])?")


def _resolve(payload: object, path: str, flag: str) -> object:
    if not _PATH.fullmatch(path):
        raise _Refused(f"{flag} {path!r} is not a path: write `key`, `key.key` or `key[n]`.")
    node = payload
    for step in _PATH_STEP.finditer(path):
        key, index = step.group(1), step.group(2)
        if not isinstance(node, dict) or key not in node:
            raise _Refused(f"{flag} {path!r} does not resolve: no key {key!r} there.")
        node = node[key]
        if index is not None:
            if not isinstance(node, list) or int(index) >= len(node):
                raise _Refused(f"{flag} {path!r} does not resolve: {key!r} has no "
                               f"element [{index}].")
            node = node[int(index)]
    return node


_ASCII_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _name_list(value: object) -> list[str] | None:
    """What counts as a list of column names: a non-empty list of strings, or of objects each
    carrying a string `name` — for the declaration and for the note that proposes one."""
    if not (isinstance(value, list) and value):
        return None
    if all(isinstance(item, str) for item in value):
        return list(value)
    if all(isinstance(item, dict) and isinstance(item.get("name"), str) for item in value):
        return [item["name"] for item in value]
    return None


def _column_names(declared: object, path: str) -> list[str]:
    if not isinstance(declared, list):
        raise _Refused(f"--names {path!r} is not a list.")
    if not declared:
        raise _Refused(f"--names {path!r} names no columns.")
    names = _name_list(declared)
    if names is None:
        raise _Refused(f"--names {path!r} must be all strings, or all objects with a string "
                       "`name`.")
    seen: dict[str, str] = {}
    for name in names:
        if not name or any(unicodedata.category(ch) == "Cc" for ch in name):
            raise _Refused(f"--names {path!r} holds an empty name or one with a control "
                           f"character: {name!r}.")
        if any(unicodedata.category(ch) == "Cs" for ch in name):
            raise _Refused(f"--names {path!r} holds a name that is not valid text (a lone "
                           f"surrogate): {name!r}.")
        # duckdb folds identifiers by ASCII case only, so that is the clash it would refuse.
        folded = name.translate(_ASCII_FOLD)
        if folded in seen:
            raise _Refused(f"--names {path!r} names a column twice: {seen[folded]!r} and "
                           f"{name!r} are the same column to the engine.")
        seen[folded] = name
    return names


def _kind(value: object) -> str:
    # `bool` first: `isinstance(True, int)` holds.
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    return "object"


def _scalar_type(values: list) -> str:
    kinds = {_kind(v) for v in values}
    if not kinds or kinds == {"str"}:
        return "VARCHAR"
    if kinds == {"bool"}:
        return "BOOLEAN"
    if kinds == {"int"}:
        if all(-(1 << 63) <= v < (1 << 63) for v in values):
            return "BIGINT"
        if all(-(1 << 127) <= v < (1 << 127) for v in values):
            return "HUGEINT"
        return "JSON"
    if kinds <= {"int", "float"}:
        return "DOUBLE"
    return "JSON"


def _column_type(cells: list) -> tuple[str, bool]:
    """@owns column_type — the declared table's column types: `(sql_type, wrap)`, where `wrap`
    says a non-list cell is stored as a one-element list.

    A column's type is a function of that column's own JSON values only — never of a sibling
    column, of what a string's text looks like, or of a vendor's declared type (O2).
    """
    present = [cell for cell in cells if cell is not None]
    if not any(isinstance(cell, list) for cell in present):
        return _scalar_type(present), False
    elements = [el for cell in present for el in (cell if isinstance(cell, list) else [cell])
                if el is not None]
    element = _scalar_type([el for el in elements if not isinstance(el, (list, dict))])
    # A list of anything but one plain kind is JSON whole, never a list of JSON: every list
    # column is then one `list_contains` can search.
    if element == "JSON" or any(isinstance(el, (list, dict)) for el in elements):
        return "JSON", False
    return f"{element}[]", True


def _quote_ident(name: str) -> str:
    """How payload text enters statement text, and the only way: as one double-quoted
    identifier. Control characters never reach it; `_column_names` refuses them."""
    return '"' + name.replace('"', '""') + '"'


def _declared_load(con, raw: bytes, rows_path: str, names_path: str, scratch: str) -> bool:
    """M1+M2: load the declared rows as `data`, one column per declared name.

    Payload text enters statement text only as `_quote_ident` identifiers, and only after the
    sandbox is locked: the unlocked load sees synthetic keys `c0…cN` and types from
    `_column_type`'s fixed vocabulary. The whole load is one boundary: whatever fails in it
    is a refusal, never a traceback. Returns whether the envelope declares `truncated`, the one
    envelope field the run still needs, so the parsed payload is not held through the query.
    """
    import duckdb

    if len(raw) > _MAX_OBJECT_SIZE:
        raise _Refused(f"stdin is over the {_MAX_OBJECT_SIZE}-byte cap.", EXIT_INPUT_ERROR)
    try:
        payload = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise _Refused(f"stdin is not one JSON document (--rows/--names need one; NDJSON "
                       f"cannot be declared): {exc}", EXIT_INPUT_ERROR) from None
    rows = _resolve(payload, rows_path, "--rows")
    names = _column_names(_resolve(payload, names_path, "--names"), names_path)
    if not isinstance(rows, list) or not all(isinstance(row, list) for row in rows):
        raise _Refused(f"--rows {rows_path!r} is not a list of lists (one list per row).")
    for i, row in enumerate(rows):
        if len(row) != len(names):
            raise _Refused(f"--rows {rows_path!r}: row {i} holds {len(row)} values but "
                           f"--names {names_path!r} names {len(names)} columns.")

    types = [_column_type([row[k] for row in rows]) for k in range(len(names))]
    try:
        _load_rows(con, rows, names, types, scratch)
    except (duckdb.Error, UnicodeError) as exc:
        # Python's JSON reader accepts what the engine's refuses (a lone surrogate), so a
        # payload can parse above and still fail here.
        # First line only: the rest names the tool's own scratch file and statement.
        reason = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
        raise _Refused(f"the payload could not be loaded: {reason}", EXIT_INPUT_ERROR) from None
    return isinstance(payload, dict) and _is_truncated(payload.get("truncated"))


def _load_rows(con, rows: list, names: list[str], types: list[tuple[str, bool]],
               scratch: str) -> None:
    ndjson = os.path.join(scratch, "rows.ndjson")
    with open(ndjson, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps({
                f"c{k}": ([cell] if wrap and cell is not None and not isinstance(cell, list)
                          else cell)
                for k, (cell, (_, wrap)) in enumerate(zip(row, types, strict=True))
            }))
            handle.write("\n")
    columns = "{" + ", ".join(f"'c{k}': '{typ}'" for k, (typ, _) in enumerate(types)) + "}"
    con.execute(
        "CREATE TABLE _rows AS SELECT * FROM read_json(?, format='newline_delimited', "
        f"columns={columns}, maximum_object_size={_MAX_OBJECT_SIZE})",
        [ndjson],
    )
    _lock(con)
    select = ", ".join(f"c{k} AS {_quote_ident(name)}" for k, name in enumerate(names))
    con.execute(f"CREATE TABLE data AS SELECT {select} FROM _rows")
    con.execute("DROP TABLE _rows")


def _inferred_load(con, raw: bytes, scratch: str) -> None:
    """The unflagged load: `read_json_auto` over the payload as it came, then the lock."""
    import duckdb

    payload_path = os.path.join(scratch, "data.json")
    with open(payload_path, "wb") as handle:
        handle.write(raw)
    try:
        con.execute(
            "CREATE TABLE data AS SELECT * FROM "
            f"read_json_auto(?, maximum_object_size={_MAX_OBJECT_SIZE})",
            [payload_path],
        )
    except duckdb.Error as exc:
        raise _Refused(f"stdin is not valid JSON or NDJSON: {exc}", EXIT_INPUT_ERROR) from None
    _lock(con)


def _load_payload(con, raw: bytes, rows_path: str | None, names_path: str | None,
                  scratch: str) -> tuple[bool, str | None]:
    """Load the payload as `data`, declared or not. Returns what the run still needs from the
    payload itself: whether a declared envelope says `truncated`, and, undeclared, the
    declaration its positional rows would need."""
    if rows_path is not None and names_path is not None:
        return _declared_load(con, raw, rows_path, names_path, scratch), None
    declaration = _positional_declaration(_single_document(raw))
    _inferred_load(con, raw, scratch)
    return False, declaration


def _lock(con) -> None:
    # A zoned value crosses into Python in the session's zone, which otherwise follows the
    # host's: a plain timestamp cast to a zoned one, or a day bucket, would shift by the host's
    # offset, and an empty `TZ` names a zone pytz cannot resolve.
    con.execute("SET TimeZone='UTC'")
    con.execute("SET enable_external_access=false")
    con.execute("SET lock_configuration=true")


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


def _run(sql: str, rows_path: str | None = None, names_path: str | None = None) -> int:
    if (rows_path is None) != (names_path is None):
        print("defender-sql: --rows and --names go together: --rows says where the positional "
              "rows are, --names where their column names are. Pass both, or neither.",
              file=sys.stderr)
        return EXIT_QUERY_ERROR
    declared = rows_path is not None

    try:
        import duckdb
    except ImportError:
        return _no_runtime("duckdb")

    # Under the flag the payload is parsed in Python, so the cap is checked before that; one
    # byte over is enough to know.
    raw = sys.stdin.buffer.read(_MAX_OBJECT_SIZE + 1) if declared else sys.stdin.buffer.read()
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
        con = duckdb.connect(":memory:")
        try:
            truncated, declaration = _load_payload(con, raw, rows_path, names_path, scratch)
        except _Refused as exc:
            print(f"defender-sql: {exc}", file=sys.stderr)
            return exc.code

        described = _describe(con)

        def hint(message: str) -> str:
            return (_declared_hint(described, message) if declared
                    else _shape_hint(described, message, declaration))

        # Printed on every run past the load, success or error: each says something the
        # answer alone would hide.
        shape_notes = ([_list_column_note(described), _json_column_note(described)] if declared
                       else [_positional_rows_note(declaration)])
        shape_notes = [note for note in shape_notes if note]

        if refusal := _arrow_refusal(con, sql):
            print(f"{refusal}{hint(refusal)}", *shape_notes, sep="\n", file=sys.stderr)
            return EXIT_QUERY_ERROR

        # The fetch is inside: handing a value to Python can fail in the engine too (#1126).
        try:
            cursor = con.execute(sql)
            records = cursor.fetchall()
        except duckdb.Error as exc:
            if missing := _MISSING_MODULE.search(str(exc)):
                return _no_runtime(missing.group(1))
            print(f"defender-sql: query error: {exc}{hint(str(exc))}", *shape_notes,
                  sep="\n", file=sys.stderr)
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
        notes = [_collision_note(renamed) if renamed else "", *shape_notes,
                 _declared_truncation_note(truncated) if declared
                 else _truncation_note(con, described)]
        for note in filter(None, notes):
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
               f"\"SELECT h.user, count(*) c {_HITS_FROM} GROUP BY 1 ORDER BY c DESC\". "
               "Positional rows behind a list of column names, declared: "
               "defender-<system> query '<query>' | defender-sql --rows values --names columns "
               "'SELECT \"source.ip\", count(*) c FROM data GROUP BY 1 ORDER BY c DESC'",
    )
    parser.add_argument(
        "--rows", metavar="PATH",
        help="Where the payload's positional rows are (a list of lists), e.g. `values` or "
             "`tables[0].rows`. With --names, `data` holds one row per row, one column per "
             "name, each column typed from its own JSON values.",
    )
    parser.add_argument(
        "--names", metavar="PATH",
        help="Where the rows' column names are: a list of strings, or of objects with a "
             "`name`, e.g. `columns`. Goes with --rows.",
    )
    parser.add_argument(
        "sql",
        help="A read-only SQL query over the `data` table (the parsed stdin payload).",
    )
    args = parser.parse_args()
    return _run(args.sql, args.rows, args.names)

if __name__ == "__main__":  # lint-log-setup: ok — a model tool — its stderr is read back by the model as plain text
    raise SystemExit(main())
