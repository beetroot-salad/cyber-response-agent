from __future__ import annotations

import argparse
import errno
import json
import os
import re
import resource
import shutil
import sys
import tempfile
import unicodedata

from defender._io import READ_LIMIT, json_safe, use_utf8_stdio

EXIT_OK = 0
EXIT_QUERY_ERROR = 1
EXIT_INPUT_ERROR = 2

#: A missing `duckdb` is a deployment fault, not the caller's mistake, so it gets its own exit
#: code (sysexits' `EX_UNAVAILABLE`): failed reduces are filed for the pitfalls curator, and
#: this one would fill the queue with identical un-actionable records.
EXIT_NO_RUNTIME = 69

#: The most a payload may hold: what a box can write to a file (`READ_LIMIT`, 64 MiB).
_MAX_PAYLOAD = READ_LIMIT

#: The most a result may hold. Below the in-box helper's own budget (64 MiB for the whole
#: command), so this tool's better message wins.
_RESULT_BUDGET = 32 << 20

#: Rows taken from the engine at a time, so a result is counted as it arrives, not after it has
#: all been held.
_FETCH_ROWS = 2048

#: The refusals of a size failure. Fixed text, at most 160 characters, no variable part: the
#: queries table keeps those 160 characters as the pitfall's merge key. The three that follow
#: a memory error say what the model can shrink, and the one for a full disk does not say
#: "memory", which would name a cause the model cannot fix.
_PAYLOAD_TOO_BIG = (
    "defender-sql: the payload is over 64 MiB, so nothing was queried. "
    "Narrow the source query (fewer rows or fields) and run it again."
)
_LOAD_OUT_OF_MEMORY = (
    "defender-sql: the payload ran out of memory while loading, so nothing was queried. "
    "Narrow the source query (fewer rows or fields)."
)
_QUERY_OUT_OF_MEMORY = (
    "defender-sql: the query ran out of memory, so nothing was answered. "
    "Ask for less: filter earlier, aggregate, or add a LIMIT."
)
_NO_ROOM = (
    "defender-sql: no room to hold the payload, so nothing was queried. "
    "Narrow the source query (fewer rows or fields)."
)
_RESULT_TOO_BIG = (
    "defender-sql: the result is over 32 MiB, so nothing is printed. "
    "Return fewer rows or columns: aggregate, add a LIMIT, or select less."
)

#: The share of the box's memory cap this process may address. The kernel kills a process that
#: reaches the cap; a limit below it turns the same overrun into an allocation error the tool
#: can catch and refuse.
_ADDRESS_SPACE_SHARE = 0.8
#: The errors that mean the box has no room for the payload (disk, quota, file-size limit, memory).
_NO_ROOM_ERRNOS = (errno.ENOSPC, errno.EDQUOT, errno.EFBIG, errno.ENOMEM)
_BOX_MEMORY = re.compile(r"(\d+(?:\.\d+)?)([bkmg]?)b?", re.IGNORECASE)
_UNITS = {"": 1, "b": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30}
_ENGINE_FIGURE = re.compile(r"([\d.]+)\s*(\w+)")
_ENGINE_UNITS = {"bytes": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40,
                 "KB": 10**3, "MB": 10**6, "GB": 10**9, "TB": 10**12}


class _SizeRefusal(Exception):
    """A size failure the tool refuses with one fixed line (exit 2). Raised out of `_run`;
    `main()` prints it and leaves at once, because unwinding the engine's connection after an
    allocation failure is where the process sometimes crashes."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class _Phase:
    """Whether the run is still loading the payload, which decides what a size failure tells
    the model to shrink."""

    loading = True


def _is_memory_error(exc: BaseException) -> bool:
    """Whether `exc` is the engine's or Python's allocation failure. By class name for the
    engine's, which is a `duckdb.Error`: every handler that would turn one into a query or load
    error must let it through to the one catch in `_run`."""
    return isinstance(exc, MemoryError) or any(
        cls.__name__ == "OutOfMemoryException" for cls in type(exc).__mro__)


def _box_memory_bytes(text: str) -> int | None:
    """`BoxSpec.memory` as written (`512m`, `2g`, plain bytes) in bytes, or None when unreadable
    or not above zero."""
    match = _BOX_MEMORY.fullmatch(text.strip())
    if match is None:
        return None
    size = int(float(match.group(1)) * _UNITS[match.group(2).lower()])
    return size or None


def _engine_figure() -> int | None:
    """The engine's own default memory limit, in bytes: what an unsandboxed run, which has no
    box cap, is held to."""
    try:
        import duckdb

        row = duckdb.sql("SELECT current_setting('memory_limit')").fetchone()
        match = _ENGINE_FIGURE.fullmatch(row[0].strip()) if row else None
        if match is None:
            return None
        return int(float(match.group(1)) * _ENGINE_UNITS[match.group(2)])
    except Exception:  # noqa: BLE001 — no limit is set when the engine will not say
        return None


def _share_one_malloc_arena() -> None:
    """Every thread the engine starts gets a 64 MiB arena of its own reserved in the address
    space (`M_ARENA_MAX` = -8), which counts against the limit below though it is rarely used;
    one shared arena keeps a small box's limit for the payload."""
    try:
        import ctypes

        ctypes.CDLL(None).mallopt(-8, 1)
    except (OSError, AttributeError):
        return


def _limit_address_space() -> None:
    """Limit this whole process's address space: about 80% of the box's cap
    (`DEFENDER_BOX_MEMORY`), or the engine's figure when there is none or it cannot be read;
    never above a lower hard limit. Done at the start of `main()` and nowhere else: tests call
    `_run` in their own process."""
    cap = _box_memory_bytes(os.environ.get("DEFENDER_BOX_MEMORY", ""))
    _share_one_malloc_arena()
    want = int(cap * _ADDRESS_SPACE_SHARE) if cap else _engine_figure()
    if want is None:
        return
    _soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    if hard != resource.RLIM_INFINITY:
        want = min(want, hard)
    try:
        resource.setrlimit(resource.RLIMIT_AS, (want, hard))
    except (ValueError, OSError):
        return


def _object_size(payload_bytes: int) -> int:
    """The engine's `maximum_object_size`, from the payload it will read. The engine reserves
    buffers of twice this up front and counts them against the memory it may use, used or not,
    so a fixed size refuses every query in a small box however small the payload."""
    return max(3 * payload_bytes + 1024, 1 << 20)

#: The form that binds `h` to the unnested struct on the search-hits shape, shared by
#: `--help`'s epilog and the query-error hint.
_HITS_FROM = "FROM (SELECT unnest(hits) h FROM data)"


def _describe(con) -> list[tuple[str, str]]:
    """`data`'s columns as `(name, type)`, or none when the engine will not say: every caller
    is advisory, and a broken introspection must not mask the answer or the real error."""
    try:
        return [(row[0], row[1]) for row in con.execute("DESCRIBE data").fetchall()]
    except Exception as exc:  # noqa: BLE001
        if _is_memory_error(exc):
            raise
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
    """Why the query must not run, if one of its `->>` arrows is misbound; else None."""
    if "->>" not in sql:
        return None
    try:
        tree = json.loads(con.execute("SELECT json_serialize_sql(?)", [sql]).fetchone()[0])
    except Exception as exc:  # noqa: BLE001 — advisory only; the query itself reports what is wrong with it
        if _is_memory_error(exc):
            raise
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
    except Exception as exc:  # noqa: BLE001
        if _is_memory_error(exc):
            raise
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
        if _is_memory_error(exc):
            raise
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
    object_size = _object_size(os.path.getsize(ndjson))
    con.execute(
        "CREATE TABLE _rows AS SELECT * FROM read_json(?, format='newline_delimited', "
        f"columns={columns}, maximum_object_size={object_size})",
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
            f"read_json_auto(?, maximum_object_size={_object_size(len(raw))})",
            [payload_path],
        )
    except duckdb.Error as exc:
        if _is_memory_error(exc):
            raise
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
            "(run `python3 defender/box/image_cli.py build` to rebuild it).",
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


def _read_stdin() -> bytes:
    """The payload bytes, read one byte past the maximum so an over-size payload is known to be
    one and refused before anything parses it. A closed stdin (`sys.stdin` is None) carries
    none, so it reads as empty and is refused like an empty one."""
    if sys.stdin is None:
        return b""
    raw = sys.stdin.buffer.read(_MAX_PAYLOAD + 1)
    if len(raw) > _MAX_PAYLOAD:
        raise _SizeRefusal(_PAYLOAD_TOO_BIG)
    return raw


def _run(sql: str, rows_path: str | None = None, names_path: str | None = None) -> int:
    if (rows_path is None) != (names_path is None):
        print("defender-sql: --rows and --names go together: --rows says where the positional "
              "rows are, --names where their column names are. Pass both, or neither.",
              file=sys.stderr)
        return EXIT_QUERY_ERROR

    try:
        import duckdb
    except ImportError:
        return _no_runtime("duckdb")

    phase = _Phase()
    scratch: str | None = None
    try:
        # The read is inside the one catch: at a small cap even the bounded read can run out.
        raw = _read_stdin()
        if not raw.strip():
            print(
                "defender-sql: no input on stdin — the payload is empty. This is NOT an "
                "empty result set: the query that produced it recorded no observation at "
                "all, so nothing here supports a claim about what is present or absent.",
                file=sys.stderr,
            )
            return EXIT_INPUT_ERROR
        scratch = tempfile.mkdtemp(prefix="defender-sql-")
        return _answer_query(duckdb, sql, raw, rows_path, names_path, scratch, phase)
    except Exception as exc:
        # The one catch for a size failure anywhere in the run. The refusal leaves `_run` with
        # the failed connection still alive in its traceback; `main()` exits without unwinding it.
        if _is_memory_error(exc):
            raise _SizeRefusal(_LOAD_OUT_OF_MEMORY if phase.loading
                               else _QUERY_OUT_OF_MEMORY) from None
        if (isinstance(exc, OSError) and phase.loading
                and exc.errno in _NO_ROOM_ERRNOS):
            raise _SizeRefusal(_NO_ROOM) from None
        raise
    finally:
        if scratch is not None:
            shutil.rmtree(scratch, ignore_errors=True)


def _fetch_result(cursor) -> tuple[list[str], str]:
    """The query's rows as JSON text and the renamed columns, taken a batch at a time into the
    result budget: a result over it prints nothing."""
    batch = cursor.fetchmany(_FETCH_ROWS)
    columns = [col[0] for col in cursor.description] if cursor.description else []
    columns, renamed = _disambiguate_columns(columns)
    parts: list[str] = []
    size = 2
    while batch:
        for record in batch:
            # `null` for a non-finite float: the model computes over these rows, and a column
            # that is number-or-null reads as one type where `"NaN"` would be a string among
            # numbers. Zone-less timestamps are UTC: the engine converts an offset to UTC when it
            # loads one, and the session's zone is UTC.
            row = json.dumps(json_safe(dict(zip(columns, record, strict=True)),
                                       non_finite="null", naive_is_utc=True), allow_nan=False)
            size += len(row) + 2
            if size > _RESULT_BUDGET:
                raise _SizeRefusal(_RESULT_TOO_BIG)
            parts.append(row)
        batch = cursor.fetchmany(_FETCH_ROWS)
    return renamed, "[" + ", ".join(parts) + "]"


def _answer_query(duckdb, sql: str, raw: bytes, rows_path: str | None, names_path: str | None,
            scratch: str, phase: _Phase) -> int:
    declared = rows_path is not None
    # Two threads: the box's CPU cap, and the strongest guard against a crash under the address
    # limit (each thread the engine starts reserves address space of its own, so the count is
    # fixed when it starts). No spill: a query that would need it stays an out-of-memory error.
    con = duckdb.connect(":memory:", config={"threads": 2, "max_temp_directory_size": "0KiB"})
    try:
        truncated, declaration = _load_payload(con, raw, rows_path, names_path, scratch)
    except _Refused as exc:
        print(f"defender-sql: {exc}", file=sys.stderr)
        return exc.code
    # Nothing after the load reads the scratch files: the tables are materialized.
    shutil.rmtree(scratch, ignore_errors=True)
    phase.loading = False

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
        renamed, text = _fetch_result(con.execute(sql))
    except duckdb.Error as exc:
        if _is_memory_error(exc):
            raise
        if missing := _MISSING_MODULE.search(str(exc)):
            return _no_runtime(missing.group(1))
        print(f"defender-sql: query error: {exc}{hint(str(exc))}", *shape_notes,
              sep="\n", file=sys.stderr)
        return EXIT_QUERY_ERROR

    # Every step that can fail on memory is done before anything is printed.
    notes = [_collision_note(renamed) if renamed else "", *shape_notes,
             _declared_truncation_note(truncated) if declared
             else _truncation_note(con, described)]
    sys.stdout.write(text)
    sys.stdout.write("\n")
    for note in filter(None, notes):
        print(note, file=sys.stderr)
    return EXIT_OK


def _refuse_and_leave(refusal: _SizeRefusal) -> None:
    """Print the refusal and leave at once, without unwinding the engine's connection: the
    process sometimes crashes there after an allocation failure, and a crash would read as a
    kill. Scratch is already gone (`_run` removes it on the way out)."""
    print(refusal.message, file=sys.stderr)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(EXIT_INPUT_ERROR)


def main() -> int:
    # The help and hints contain an em-dash and a lead's shell may be the `C` locale. Done
    # here, not at import, so in-process imports leave the host's streams alone.
    use_utf8_stdio()
    _limit_address_space()
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
    try:
        return _run(args.sql, args.rows, args.names)
    except _SizeRefusal as refusal:
        _refuse_and_leave(refusal)
        return EXIT_INPUT_ERROR  # unreachable: the process has left

if __name__ == "__main__":  # lint-log-setup: ok — a model tool — its stderr is read back by the model as plain text
    raise SystemExit(main())
