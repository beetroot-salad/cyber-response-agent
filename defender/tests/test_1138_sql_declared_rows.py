"""#1138 — model-declared positional rows for `defender-sql`: `--rows PATH --names PATH`.

A positional payload is a header of names plus rows as bare arrays — ES|QL `{columns, values}`
today, Splunk `fields`/`rows`, Azure `tables[0].columns/rows` or an MCP server's shape
tomorrow. Unflagged, `read_json_auto` types the WHOLE row array from what its cells hold
(`JSON[][]`, `VARCHAR[][]`, `BIGINT[][]`, `TIMESTAMP[][]`), so a lead had to map positions and
unpack `v[N]->>'$'` — and on an all-text payload that recipe crashed outright. Under the flags
the lead says where the rows and the names are, and `data` is one row per row, one column per
name, each column typed from ITS OWN JSON values.

Every test drives the real program's own `main()` in a warm child process (`run_sql_warm`, see `_sql_warm.py`; the timing test and `--help` still spawn it fresh via `run_sql_py`: the argv after `defender-sql`,
the payload on stdin) and asserts what the lead observes — the JSON rows on stdout, the exit
code, the stderr text, the types `DESCRIBE data` prints. Each test names the obligation of the
#1138 design it pins (O1–O10, M7). Every negative is paired with a positive control on the same
payload under the complementary condition, so no refusal or absent note can pass vacuously.

The rest of #1138's spec lives beside the tests it extends: the gate (O7) in `test_permission.py`
and, end to end through a replayed gather lead, in `e2e/test_query_tool_611.py`; the overflow
hint and the payload-view footer (O8) in `test_read_file_bounded.py` and `test_payload_view.py`;
the doc's flagged examples, the exit-code paragraph and the `unnest` census (O9) in
`test_sql_idioms.py`, whose ES|QL tests moved to the declared idiom.

Not pinned: the 1 GiB `_MAX_OBJECT_SIZE` refusal (exit 2, before `json.loads`). The only probe
the design gives is a stdin over 1 GiB, which is not a test this suite can afford to run.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from defender._io import read_text_utf8
from defender.scripts.adapters.elastic_adapter import esql_payload
from defender.tests._by_path import DEFENDER
from defender.tests._defender_sql import (
    EXIT_INPUT_ERROR,
    EXIT_OK,
    EXIT_QUERY_ERROR,
    assert_query_error,
    run_sql_py,
)
from defender.tests._sql_warm import run_sql_warm

_DOC = DEFENDER / "skills" / "gather" / "defender-sql.md"

#: Shaped by the REAL adapter step (`esql_payload`), so the envelope carries `query` and
#: `row_count` beside `columns`/`values` exactly as a lead's gather_raw file does. The rows are
#: chosen so a lexical `> 9` and a numeric one disagree: '412' and '10' sort BELOW '9' as text.
_ESQL_QUERY = "FROM logs-* | STATS failed = COUNT(*) BY source.ip"
_ESQL = esql_payload(_ESQL_QUERY, {
    "columns": [{"name": "failed", "type": "long"}, {"name": "source.ip", "type": "ip"}],
    "values": [
        [412, "203.0.113.7"],
        [10, "203.0.113.7"],
        [9, "203.0.113.7"],
        [3, "203.0.113.40"],
        [500, "198.51.100.22"],
    ],
})


def _text(payload: dict | list | str) -> str:
    return payload if isinstance(payload, str) else json.dumps(payload)


def _flag(payload, sql: str, rows: str = "values", names: str = "columns"):
    """`cat <payload> | defender-sql --rows <rows> --names <names> '<sql>'`."""
    return run_sql_warm("--rows", rows, "--names", names, sql, stdin=_text(payload))


def _plain(payload, sql: str):
    """`cat <payload> | defender-sql '<sql>'` — no declaration."""
    return run_sql_warm(sql, stdin=_text(payload))


def _ok(proc: subprocess.CompletedProcess) -> list:
    assert proc.returncode == EXIT_OK, f"exit {proc.returncode}: {proc.stderr!r}"
    return json.loads(proc.stdout)


def _schema(payload, rows: str = "values", names: str = "columns") -> list[tuple[str, str]]:
    """`DESCRIBE data` under the flags, as `(name, type)` in table order."""
    return [(r["column_name"], r["column_type"])
            for r in _ok(_flag(payload, "DESCRIBE data", rows, names))]


def _refused(proc: subprocess.CompletedProcess, code: int, *mentions: str | tuple[str, ...]) -> None:
    """Refused LOUDLY: the table's exit code, nothing on stdout, the tool's own message (not a
    crash — CPython also exits 1 on an uncaught exception), naming the defect. A mention given
    as a tuple is a set of alternatives: the message names the defect's locus by ONE of them
    (the PATH as declared, or the flag it was declared with)."""
    detail = f"exit {proc.returncode}, stdout {proc.stdout!r}, stderr {proc.stderr!r}"
    assert proc.returncode == code, detail
    assert proc.stdout == "", detail
    assert "Traceback" not in proc.stderr, detail
    assert "defender-sql" in proc.stderr, detail
    for mention in mentions:
        alternatives = (mention,) if isinstance(mention, str) else mention
        assert any(a in proc.stderr for a in alternatives), (
            f"the refusal does not name {' or '.join(map(repr, alternatives))}: {detail}")


# ============================================================ O1: query the rows BY NAME


def test_o1_a_flagged_esql_payload_is_filtered_by_name_and_compares_numbers_as_numbers():
    """O1: the design's own witness — `"source.ip" = '…' AND failed > 9` over an ES|QL payload,
    no position, no `->>`, no cast. `failed` must be a NUMBER: a text-typed column answers this
    filter with a Binder Error (VARCHAR vs INTEGER), and a text column compared as text answers
    it with nothing (`'412' > '9'` is false). Only the numeric typing returns 412 and 10, and
    returns them as JSON numbers."""
    rows = _ok(_flag(_ESQL, 'SELECT failed FROM data WHERE "source.ip" = \'203.0.113.7\' '
                            "AND failed > 9 ORDER BY failed DESC"))
    assert rows == [{"failed": 412}, {"failed": 10}]
    assert all(type(r["failed"]) is int for r in rows)

    assert _ok(_flag(_ESQL, "SELECT sum(failed) AS s, count(*) AS n FROM data")) == [
        {"s": 934, "n": 5}]
    # The other direction of the same trap: lexically '412' < '9' and '10' < '9' too.
    assert _ok(_flag(_ESQL, "SELECT count(*) AS n FROM data WHERE failed < 9")) == [{"n": 1}]


def test_o1_describe_lists_exactly_the_declared_names_in_order():
    """O1: `DESCRIBE data` lists the declared names, in the names' order — and nothing of the
    envelope: under the flags `query`, `row_count`, `columns` and `values` are not columns."""
    assert _schema(_ESQL) == [("failed", "BIGINT"), ("source.ip", "VARCHAR")]
    reordered = dict(_ESQL, columns=[{"name": "hits", "type": "ip"}, {"name": "a", "type": "long"}],
                     values=[[r[1], r[0]] for r in _ESQL["values"]])
    assert [n for n, _ in _schema(reordered)] == ["hits", "a"]
    assert_query_error(_flag(_ESQL, "SELECT row_count FROM data"),
                       "an envelope field was queryable as a column of the declared table")


def test_o1_names_as_plain_strings_and_as_name_objects_load_the_same_table():
    """O1: names are a list of strings (Splunk `fields`) or of objects carrying a string `name`
    (ES|QL `columns`, Azure `columns`; their other fields — `type` — ignored). Same rows, same
    table, same answer; the keys under which they sit are the lead's to declare."""
    splunk = {"fields": ["failed", "source.ip"], "rows": _ESQL["values"], "count": 5}
    sql = 'SELECT "source.ip", failed FROM data ORDER BY failed'
    as_objects = _ok(_flag(_ESQL, sql))
    as_strings = _ok(_flag(splunk, sql, rows="rows", names="fields"))
    assert as_strings == as_objects
    assert as_objects[0] == {"source.ip": "203.0.113.40", "failed": 3}
    extra = dict(_ESQL, columns=[{"name": "failed", "type": "long", "original_types": ["x"]},
                                 {"type": "ip", "name": "source.ip"}])
    assert _ok(_flag(extra, sql)) == as_objects


#: Azure Monitor's shape: rows nested one list and one key down, a SECOND table beside the
#: first so an index that is ignored (or read as 0 whatever it says) answers wrong.
_AZURE = {"tables": [
    {"name": "PrimaryResult",
     "columns": [{"name": "TimeGenerated", "type": "datetime"}, {"name": "Computer", "type": "string"},
                 {"name": "Count", "type": "long"}],
     "rows": [["2026-08-07T11:00:00Z", "web-1", 5], ["2026-08-07T12:00:00Z", "db-1", 7]]},
    {"name": "Other",
     "columns": [{"name": "Computer", "type": "string"}, {"name": "Count", "type": "long"}],
     "rows": [["mail-1", 40]]},
]}


@pytest.mark.parametrize("spelling", ["space", "equals"])
def test_o1_a_nested_path_with_an_index_resolves(spelling):
    """O1: PATH is `key('.'key)*`, each key optionally `[n]`, resolved from the top-level
    object — `tables[0].rows` — in both argparse spellings, `--rows X` and `--rows=X`. The
    second table is reached by ITS index, not by the first's."""
    def run(sql: str, n: int):
        rows, names = f"tables[{n}].rows", f"tables[{n}].columns"
        if spelling == "equals":
            return run_sql_warm(f"--rows={rows}", f"--names={names}", sql, stdin=json.dumps(_AZURE))
        return run_sql_warm("--rows", rows, "--names", names, sql, stdin=json.dumps(_AZURE))

    assert _ok(run("SELECT Computer, Count FROM data WHERE Count > 6", 0)) == [
        {"Computer": "db-1", "Count": 7}]
    assert _ok(run("SELECT Computer, Count FROM data", 1)) == [{"Computer": "mail-1", "Count": 40}]
    assert [r["column_name"] for r in _ok(run("DESCRIBE data", 0))] == [
        "TimeGenerated", "Computer", "Count"]


def test_o1_an_empty_row_list_is_a_zero_row_table_of_varchar_columns():
    """O1: an ES|QL query that matched nothing still declares its columns. The table exists,
    has the declared names, holds zero rows, and — with no value to type from — every column is
    VARCHAR (the all-null rule), so `count(*)` answers 0 rather than an error."""
    empty = esql_payload(_ESQL_QUERY, {"columns": _ESQL["columns"], "values": []})
    assert _schema(empty) == [("failed", "VARCHAR"), ("source.ip", "VARCHAR")]
    assert _ok(_flag(empty, "SELECT count(*) AS n FROM data")) == [{"n": 0}]
    assert _ok(_flag(empty, 'SELECT * FROM data WHERE "source.ip" = \'x\'')) == []


def test_o1_a_declared_name_that_spells_a_synthetic_or_internal_name_keeps_its_own_values():
    """O1: the tool may load under keys of its own, but a name the payload DECLARES is the
    lead's — `c1` declared first and `c0` second must each hold their own cells, and names that
    are SQL keywords or the tool's table names are columns like any other."""
    payload = {"hdr": ["c1", "c0", "select", "data", "_rows"], "recs": [[1, "a", "k", "d", "r"]]}
    assert _ok(_flag(payload, 'SELECT c0, c1, "select", "data", "_rows" FROM data',
                     rows="recs", names="hdr")) == [
        {"c0": "a", "c1": 1, "select": "k", "data": "d", "_rows": "r"}]


# ------------------------------------ M7 (O1): the truncation note, one rule on both paths


_ABSENT = object()
#: The top-level `truncated` values that mean "the source stopped early", and those that do not.
#: One table for BOTH paths: a source that writes `1` or `"true"` is truncated whichever way
#: the lead reads its payload.
_TRUNCATED = [(True, True), (1, True), ("true", True),
              (False, False), (0, False), ("false", False), (_ABSENT, False)]


@pytest.mark.parametrize("path", ["unflagged", "flagged"])
@pytest.mark.parametrize(("value", "fires"), _TRUNCATED,
                         ids=["true", "1", "str-true", "false", "0", "str-false", "absent"])
def test_m7_the_truncation_note_fires_on_the_same_values_on_both_paths(path, value, fires):
    """M7 (O1): the truncation note is one rule. Unflagged it is read off `data` (a search-hits
    envelope); flagged, `truncated` is no column of `data`, so it is read off the parsed
    envelope — and both fire on `true`, `1` and `"true"`, and on nothing else. The flagged
    wording is generic, never the search-hits prose about `hits`. Neither payload has a list,
    JSON or positional column, so a silent run is an EMPTY stderr."""
    flagged = path == "flagged"
    payload: dict = (dict(_ESQL) if flagged
                     else {"total": 3, "returned": 2, "hits": [{"u": "a"}, {"u": "b"}]})
    if value is not _ABSENT:
        payload["truncated"] = value
    proc = (_flag(payload, _SQL) if flagged
            else _plain(payload, "SELECT count(*) AS n FROM (SELECT unnest(hits) h FROM data)"))
    assert _ok(proc) == [{"n": 5 if flagged else 2}]
    if fires:
        assert "truncated" in proc.stderr.lower(), f"`truncated: {value!r}` printed no note"
        if flagged:
            assert "hits" not in proc.stderr, "the flagged note borrowed the search-hits prose"
    else:
        assert proc.stderr.strip() == "", f"`truncated: {value!r}` printed {proc.stderr!r}"


# ================================================ O2: a column's type is its own JSON values


#: (id, the column's cells, the type `DESCRIBE data` must print for it). One column per payload,
#: so each type is a function of those cells and nothing beside them.
_TYPES = [
    ("str", ["a", "b"], "VARCHAR"),
    ("str-and-null", ["a", None], "VARCHAR"),
    ("int", [1, 2], "BIGINT"),
    ("int64-bounds", [2**63 - 1, -(2**63)], "BIGINT"),
    ("int-and-float", [1, 2.5], "DOUBLE"),
    ("one-point-oh-is-a-float", [1.0, 2.0], "DOUBLE"),
    ("int-and-one-point-oh", [1, 1.0], "DOUBLE"),
    ("bool", [True, False], "BOOLEAN"),
    ("bool-is-not-int", [True, 1], "JSON"),
    ("all-null", [None, None], "VARCHAR"),
    ("over-int64", [2**64 - 1, 1], "HUGEINT"),
    ("under-int64", [-(2**63) - 1], "HUGEINT"),
    ("int128-max", [2**127 - 1], "HUGEINT"),
    ("over-int128", [2**127, 1], "JSON"),
    ("objects", [{"a": 1}, {"b": 2}], "JSON"),
    ("str-and-int", ["a", 1], "JSON"),
    ("str-and-object", ["a", {"a": 1}], "JSON"),
    ("list-of-str", [["a", "b"], ["c"]], "VARCHAR[]"),
    ("list-and-scalar", [["a"], "b", None, []], "VARCHAR[]"),
    ("list-of-int", [[1, 2], 3], "BIGINT[]"),
    ("list-of-bool", [[True, False]], "BOOLEAN[]"),
    ("list-of-int-and-float", [[1, 2.5]], "DOUBLE[]"),
    ("list-of-null", [[None], None], "VARCHAR[]"),
    # A list whose elements mix kinds is a JSON column, not `JSON[]` — there is no JSON[] (R3).
    ("list-of-mixed-kinds", [["a", 1]], "JSON"),
    ("list-and-scalar-of-mixed-kinds", [["x", 5], "c"], "JSON"),
    ("list-holding-a-list", [[["a"]]], "JSON"),
    ("list-holding-an-object", [[{"a": 1}]], "JSON"),
]


@pytest.mark.parametrize(("cells", "expected"), [(c, t) for _, c, t in _TYPES],
                         ids=[i for i, _, _ in _TYPES])
def test_o2_a_columns_type_follows_the_design_rule_over_its_own_cells(cells, expected):
    """O2: the column-type rule, case by case — bool checked before int, `1.0` a float, int64
    then int128 then JSON, all-null VARCHAR, any list cell a list column (element type by the
    same rule; a nested list or object makes the column JSON), anything else JSON."""
    payload = {"hdr": ["x"], "recs": [[c] for c in cells]}
    assert _schema(payload, rows="recs", names="hdr") == [("x", expected)]


def test_o2_values_come_back_as_the_json_kind_they_were_sent_as():
    """O2: the typed column hands its value back exactly — a HUGEINT holds 2**64-1 to the unit
    (a DOUBLE would round it), a BOOLEAN answers `true`, a float column answers a float."""
    payload = {"hdr": ["big", "flag", "ratio"],
               "recs": [[2**64 - 1, True, 1], [2, False, 2.5]]}
    assert _ok(_flag(payload, "SELECT * FROM data ORDER BY ratio", rows="recs", names="hdr")) == [
        {"big": 18446744073709551615, "flag": True, "ratio": 1.0},
        {"big": 2, "flag": False, "ratio": 2.5},
    ]
    assert _ok(_flag(payload, "SELECT count(*) AS n FROM data WHERE big > 18446744073709551614 "
                              "AND flag", rows="recs", names="hdr")) == [{"n": 1}]


def test_o2_a_column_types_the_same_whatever_its_siblings_hold():
    """O2: `read_json_auto` typed the whole row array together, so `source.ip` was VARCHAR or
    JSON depending on whether a NUMBER sat beside it. Declared, the same column is the same
    type beside a number, beside text, and alone."""
    def schema(names, row):
        return _schema({"hdr": names, "recs": [row]}, rows="recs", names="hdr")

    assert schema(["ip", "n"], ["203.0.113.7", 5]) == [("ip", "VARCHAR"), ("n", "BIGINT")]
    assert schema(["ip", "host"], ["203.0.113.7", "web-1"]) == [("ip", "VARCHAR"), ("host", "VARCHAR")]
    assert schema(["ip"], ["203.0.113.7"]) == [("ip", "VARCHAR")]
    assert schema(["m", "n"], [1, 5]) == [("m", "BIGINT"), ("n", "BIGINT")]


def test_o2_a_vendors_declared_type_decides_nothing():
    """O2: ES|QL's `type` is the vendor's word, not the payload's value. A `long` column whose
    cells are strings is VARCHAR; a `keyword` column whose cells are numbers is BIGINT."""
    lying = esql_payload(_ESQL_QUERY, {
        "columns": [{"name": "code", "type": "long"}, {"name": "n", "type": "keyword"}],
        "values": [["4625", 1], ["4624", 2]],
    })
    assert _schema(lying) == [("code", "VARCHAR"), ("n", "BIGINT")]
    assert _ok(_flag(lying, "SELECT n FROM data WHERE code = '4625'")) == [{"n": 1}]


#: Text that LOOKS like something else. Each must stay the source's text, byte for byte: a
#: TIMESTAMP would drop the nanoseconds and rewrite the offset to UTC, a DATE or BIGINT or
#: BOOLEAN would re-render the value.
_LOOKALIKES = [
    "2026-08-07T11:32:52.123456789Z",
    "2026-08-07T13:32:52+02:00",
    "2026-08-07 11:32:52",
    "2026-08-07",
    "412",
    "true",
    "0x1F",
]


def test_o2_text_that_looks_like_a_time_or_a_number_stays_varchar_byte_identical():
    """O2: never what a string's text looks like. An ISO-time column (read_json_auto made it
    TIMESTAMP[][]) stays VARCHAR and round-trips byte-identical — #1125 stays won't-fix, the
    strings are the source's text — and so does every other lookalike."""
    payload = {"hdr": ["t"], "recs": [[s] for s in _LOOKALIKES]}
    assert _schema(payload, rows="recs", names="hdr") == [("t", "VARCHAR")]
    assert [r["t"] for r in _ok(_flag(payload, "SELECT t FROM data", rows="recs", names="hdr"))] \
        == _LOOKALIKES
    assert _ok(_flag(payload, "SELECT count(*) AS n FROM data "
                              "WHERE t = '2026-08-07T13:32:52+02:00'", rows="recs", names="hdr")) \
        == [{"n": 1}]


def test_o2_an_all_text_payload_filters_by_name_without_malformed_json():
    """O2 / C2: the payload shape that CRASHED the taught recipe — every cell text, so
    `read_json_auto` made `values` VARCHAR[][] and `(v[N]->>'$')` answered `Malformed JSON`.
    Declared, it is two VARCHAR columns and a plain filter."""
    all_text = esql_payload("FROM logs-* | KEEP host.name, user.name", {
        "columns": [{"name": "host.name", "type": "keyword"}, {"name": "user.name", "type": "keyword"}],
        "values": [["web-1", "alice"], ["web-1", "bob"], ["db-1", "alice"]],
    })
    proc = _flag(all_text, 'SELECT "host.name" FROM data WHERE "user.name" = \'alice\' ORDER BY 1')
    assert _ok(proc) == [{"host.name": "db-1"}, {"host.name": "web-1"}]
    assert "Malformed JSON" not in proc.stderr
    assert proc.stderr.strip() == ""


# ============================================== O3: every declaration mistake fails loudly


_AZ = json.dumps(_AZURE)
_ES = json.dumps(_ESQL)
_SQL = "SELECT count(*) AS n FROM data"


@dataclass(frozen=True)
class _Defect:
    """One row of the exit-code table: the defective call, its exit, what the message must
    name — and the SAME call with the defect removed, which must load and answer `n`."""
    argv: tuple[str, ...]
    stdin: str
    exit: int
    mentions: tuple[str | tuple[str, ...], ...]
    fixed_argv: tuple[str, ...]
    fixed_stdin: str
    n: int


def _recs(names, rows, **extra) -> str:
    return json.dumps({"hdr": names, "recs": rows, **extra})


_FLAGS = ("--rows", "recs", "--names", "hdr")

_DEFECTS: dict[str, _Defect] = {
    # -- argparse syntax -> 2
    "rows-flag-without-a-value": _Defect(
        (_SQL, "--names", "columns", "--rows"), _ES, EXIT_INPUT_ERROR, ("--rows", "expected one argument"),
        (_SQL, "--names", "columns", "--rows", "values"), _ES, 5),
    "names-flag-without-a-value": _Defect(
        (_SQL, "--rows", "values", "--names"), _ES, EXIT_INPUT_ERROR, ("--names", "expected one argument"),
        (_SQL, "--rows", "values", "--names", "columns"), _ES, 5),
    "unknown-flag": _Defect(
        ("--bogus", "x", "--rows", "values", "--names", "columns", _SQL), _ES, EXIT_INPUT_ERROR, ("--bogus",),
        ("--rows", "values", "--names", "columns", _SQL), _ES, 5),
    # -- only one of the two flags -> 1
    "only-rows": _Defect(
        ("--rows", "values", _SQL), _ES, EXIT_QUERY_ERROR, ("--names",),
        ("--rows", "values", "--names", "columns", _SQL), _ES, 5),
    "only-names": _Defect(
        ("--names", "columns", _SQL), _ES, EXIT_QUERY_ERROR, ("--rows",),
        ("--rows", "values", "--names", "columns", _SQL), _ES, 5),
    # -- a path that does not resolve -> 1
    "rows-key-missing": _Defect(
        ("--rows", "valuez", "--names", "columns", _SQL), _ES, EXIT_QUERY_ERROR, ("valuez",),
        ("--rows", "values", "--names", "columns", _SQL), _ES, 5),
    "names-key-missing": _Defect(
        ("--rows", "values", "--names", "columnz", _SQL), _ES, EXIT_QUERY_ERROR, ("columnz",),
        ("--rows", "values", "--names", "columns", _SQL), _ES, 5),
    "index-past-the-end": _Defect(
        ("--rows", "tables[2].rows", "--names", "tables[2].columns", _SQL), _AZ, EXIT_QUERY_ERROR,
        ("tables[2]",),
        ("--rows", "tables[1].rows", "--names", "tables[1].columns", _SQL), _AZ, 1),
    "negative-index": _Defect(
        ("--rows", "tables[-1].rows", "--names", "tables[-1].columns", _SQL), _AZ, EXIT_QUERY_ERROR,
        ("tables[-1]",),
        ("--rows", "tables[0].rows", "--names", "tables[0].columns", _SQL), _AZ, 2),
    "list-without-an-index": _Defect(
        ("--rows", "tables.rows", "--names", "tables[0].columns", _SQL), _AZ, EXIT_QUERY_ERROR,
        ("tables.rows",),
        ("--rows", "tables[0].rows", "--names", "tables[0].columns", _SQL), _AZ, 2),
    "index-on-an-object": _Defect(
        ("--rows", "meta[0]", "--names", "hdr", _SQL), json.dumps({"meta": {"0": [[1]]}, "hdr": ["a"]}),
        EXIT_QUERY_ERROR, ("meta[0]",),
        _FLAGS + (_SQL,), _recs(["a"], [[1]]), 1),
    "key-under-a-scalar": _Defect(
        ("--rows", "row_count.values", "--names", "columns", _SQL), _ES, EXIT_QUERY_ERROR,
        ("row_count.values",),
        ("--rows", "values", "--names", "columns", _SQL), _ES, 5),
    "a-dotted-key-cannot-be-declared": _Defect(
        ("--rows", "a.b", "--names", "hdr", _SQL), json.dumps({"a.b": [[1]], "hdr": ["x"]}),
        EXIT_QUERY_ERROR, ("a.b",),
        ("--rows", "ab", "--names", "hdr", _SQL), json.dumps({"ab": [[1]], "hdr": ["x"]}), 1),
    "a-top-level-array-cannot-be-declared": _Defect(
        ("--rows", "recs", "--names", "hdr", _SQL), json.dumps([{"hdr": ["a"], "recs": [[1]]}]),
        EXIT_QUERY_ERROR, (("recs", "array", "object"),),
        _FLAGS + (_SQL,), _recs(["a"], [[1]]), 1),
    # -- rows not a list of lists -> 1
    "rows-a-scalar": _Defect(
        ("--rows", "row_count", "--names", "columns", _SQL), _ES, EXIT_QUERY_ERROR, ("row_count",),
        ("--rows", "values", "--names", "columns", _SQL), _ES, 5),
    "rows-a-string": _Defect(
        _FLAGS + (_SQL,), _recs(["a"], "[[1]]"), EXIT_QUERY_ERROR, (("recs", "--rows"),),
        _FLAGS + (_SQL,), _recs(["a"], [[1]]), 1),
    "rows-a-list-of-objects": _Defect(
        _FLAGS + (_SQL,), _recs(["a"], [{"a": 1}, {"a": 2}]), EXIT_QUERY_ERROR, (("recs", "--rows"),),
        _FLAGS + (_SQL,), _recs(["a"], [[1], [2]]), 2),
    "rows-with-one-non-list": _Defect(
        _FLAGS + (_SQL,), _recs(["a"], [[1], 2, [3]]), EXIT_QUERY_ERROR, (("recs", "--rows"),),
        _FLAGS + (_SQL,), _recs(["a"], [[1], [2], [3]]), 3),
    "rows-an-object": _Defect(
        _FLAGS + (_SQL,), _recs(["a"], {"0": [1]}), EXIT_QUERY_ERROR, (("recs", "--rows"),),
        _FLAGS + (_SQL,), _recs(["a"], [[1]]), 1),
    # -- names not all strings / all {name: string} -> 1
    "names-a-string": _Defect(
        _FLAGS + (_SQL,), _recs("a", [[1]]), EXIT_QUERY_ERROR, (("hdr", "--names"),),
        _FLAGS + (_SQL,), _recs(["a"], [[1]]), 1),
    "names-mix-strings-and-objects": _Defect(
        _FLAGS + (_SQL,), _recs(["a", {"name": "b"}], [[1, 2]]), EXIT_QUERY_ERROR, (("hdr", "--names"),),
        _FLAGS + (_SQL,), _recs(["a", "b"], [[1, 2]]), 1),
    "names-hold-a-number": _Defect(
        _FLAGS + (_SQL,), _recs(["a", 5], [[1, 2]]), EXIT_QUERY_ERROR, (("hdr", "--names"),),
        _FLAGS + (_SQL,), _recs(["a", "5"], [[1, 2]]), 1),
    "names-object-without-a-name": _Defect(
        _FLAGS + (_SQL,), _recs([{"name": "a"}, {"label": "b"}], [[1, 2]]), EXIT_QUERY_ERROR, (("hdr", "--names"),),
        _FLAGS + (_SQL,), _recs([{"name": "a"}, {"name": "b", "label": "b"}], [[1, 2]]), 1),
    "names-object-with-a-numeric-name": _Defect(
        _FLAGS + (_SQL,), _recs([{"name": 7}], [[1]]), EXIT_QUERY_ERROR, (("hdr", "--names"),),
        _FLAGS + (_SQL,), _recs([{"name": "7"}], [[1]]), 1),
    # -- zero names -> 1
    "zero-names": _Defect(
        _FLAGS + (_SQL,), _recs([], []), EXIT_QUERY_ERROR, (("hdr", "--names"),),
        _FLAGS + (_SQL,), _recs(["a"], []), 0),
    # -- a row whose length is not the number of names -> 1
    "row-shorter-than-the-names": _Defect(
        _FLAGS + (_SQL,), _recs(["a", "b"], [[1, 2], [3]]), EXIT_QUERY_ERROR, (("recs", "--rows"),),
        _FLAGS + (_SQL,), _recs(["a", "b"], [[1, 2], [3, None]]), 2),
    "row-longer-than-the-names": _Defect(
        _FLAGS + (_SQL,), _recs(["a", "b"], [[1, 2], [3, 4, 5]]), EXIT_QUERY_ERROR, (("recs", "--rows"),),
        _FLAGS + (_SQL,), _recs(["a", "b", "c"], [[1, 2, None], [3, 4, 5]]), 2),
    # -- an empty name, or one with a control character -> 1
    "empty-name": _Defect(
        _FLAGS + (_SQL,), _recs(["a", ""], [[1, 2]]), EXIT_QUERY_ERROR, (("hdr", "--names"),),
        _FLAGS + (_SQL,), _recs(["a", " "], [[1, 2]]), 1),
    "name-with-a-newline": _Defect(
        _FLAGS + (_SQL,), _recs(["a\nb"], [[1]]), EXIT_QUERY_ERROR, (("hdr", "--names"),),
        _FLAGS + (_SQL,), _recs(["a b"], [[1]]), 1),
    "name-with-a-nul": _Defect(
        _FLAGS + (_SQL,), _recs(["a\x00b"], [[1]]), EXIT_QUERY_ERROR, (("hdr", "--names"),),
        _FLAGS + (_SQL,), _recs(["a0b"], [[1]]), 1),
    "name-with-an-escape-sequence": _Defect(
        _FLAGS + (_SQL,), _recs(["\x1b[31mred"], [[1]]), EXIT_QUERY_ERROR, (("hdr", "--names"),),
        _FLAGS + (_SQL,), _recs(["[31mred"], [[1]]), 1),
    "name-with-a-tab": _Defect(
        _FLAGS + (_SQL,), _recs(["a\tb"], [[1]]), EXIT_QUERY_ERROR, (("hdr", "--names"),),
        _FLAGS + (_SQL,), _recs(["a-b"], [[1]]), 1),
    # DEL and the C1 range are control characters too (Unicode `Cc`), not only ord < 32.
    "name-with-a-del": _Defect(
        _FLAGS + (_SQL,), _recs(["a\x7fb"], [[1]]), EXIT_QUERY_ERROR, (("hdr", "--names"),),
        _FLAGS + (_SQL,), _recs(["a~b"], [[1]]), 1),
    "name-with-a-c1-control": _Defect(
        _FLAGS + (_SQL,), _recs(["a\x85b"], [[1]]), EXIT_QUERY_ERROR, (("hdr", "--names"),),
        _FLAGS + (_SQL,), _recs(["a\u2026b"], [[1]]), 1),
    # A lone UTF-16 surrogate parses in Python but is no text the engine can name a column with:
    # a declaration defect (R2), refused — never a traceback out of the load.
    "name-with-a-lone-surrogate": _Defect(
        _FLAGS + (_SQL,), _recs(["a\ud800b"], [[1]]), EXIT_QUERY_ERROR, (("hdr", "--names"),),
        _FLAGS + (_SQL,), _recs(["ab"], [[1]]), 1),
    # -- two names equal under ASCII case folding -> 1
    "ascii-case-clash": _Defect(
        _FLAGS + (_SQL,), _recs(["Host", "host"], [["a", "b"]]), EXIT_QUERY_ERROR, ("Host", "host"),
        _FLAGS + (_SQL,), _recs(["Host", "host.name"], [["a", "b"]]), 1),
    "exact-duplicate": _Defect(
        _FLAGS + (_SQL,), _recs(["src.ip", "src.ip"], [["a", "b"]]), EXIT_QUERY_ERROR, ("src.ip",),
        _FLAGS + (_SQL,), _recs(["src.ip", "dst.ip"], [["a", "b"]]), 1),
    # -- stdin empty, not JSON, or not ONE JSON document -> 2
    "empty-stdin": _Defect(
        ("--rows", "values", "--names", "columns", _SQL), "", EXIT_INPUT_ERROR, (("no input", "empty"),),
        ("--rows", "values", "--names", "columns", _SQL), _ES, 5),
    "whitespace-stdin": _Defect(
        ("--rows", "values", "--names", "columns", _SQL), " \n", EXIT_INPUT_ERROR, (("no input", "empty"),),
        ("--rows", "values", "--names", "columns", _SQL), _ES, 5),
    "not-json": _Defect(
        ("--rows", "values", "--names", "columns", _SQL), "## Query Results\n\n- 197 events\n",
        EXIT_INPUT_ERROR, ("JSON",),
        ("--rows", "values", "--names", "columns", _SQL), _ES, 5),
    "truncated-json": _Defect(
        ("--rows", "values", "--names", "columns", _SQL), _ES[:-5], EXIT_INPUT_ERROR, ("JSON",),
        ("--rows", "values", "--names", "columns", _SQL), _ES, 5),
    "ndjson": _Defect(
        ("--rows", "values", "--names", "columns", _SQL), _ES + "\n" + _ES + "\n", EXIT_INPUT_ERROR,
        ("JSON",),
        ("--rows", "values", "--names", "columns", _SQL), _ES + "\n", 5),
}


@pytest.mark.parametrize("case", list(_DEFECTS), ids=list(_DEFECTS))
def test_o3_every_declaration_defect_is_refused_with_its_exit_and_the_fix_loads(case):
    """O3: one row of the exit-code table per case. The defective call exits with the table's
    code, prints nothing on stdout, and says what is wrong in the tool's own words — never a
    traceback, never a silently wrong table. What the words must carry is the defect's locus: a
    PATH that does not resolve is quoted as declared, a rows or names defect names its path or
    its flag, a clash names the clashing names. The paired control is the same call with the
    defect removed: it loads and answers the right count, so every refusal above is about the
    defect and not about the payload, the query or the flags in general."""
    d = _DEFECTS[case]
    _refused(run_sql_warm(*d.argv, stdin=d.stdin), d.exit, *d.mentions)
    assert _ok(run_sql_warm(*d.fixed_argv, stdin=d.fixed_stdin)) == [{"n": d.n}]


def test_o3_names_that_differ_only_by_non_ascii_case_are_distinct_columns():
    """O3's positive side of the case rule: duckdb folds ASCII case only (C9), so the tool
    refuses exactly that. `É`/`é`, `Straße`/`STRASSE` and `K`/KELVIN SIGN are distinct to
    duckdb — and each pair is EQUAL under Python's `.lower()` or `.casefold()`, so a refusal
    built on either of those would wrongly reject a payload duckdb loads."""
    names = ["É", "é", "Straße", "STRASSE", "K", "K"]
    payload = {"hdr": names, "recs": [[1, 2, 3, 4, 5, 6]]}
    assert [n for n, _ in _schema(payload, rows="recs", names="hdr")] == names
    rows = _ok(_flag(payload, 'SELECT "é", "É", "STRASSE", "Straße", "K", "K" FROM data',
                     rows="recs", names="hdr"))
    assert [list(r.values()) for r in rows] == [[2, 1, 4, 3, 6, 5]]


# ======================================= O4: a list column never answers as if it were scalar


#: ES|QL returns a multi-valued keyword field as a list in one row and a bare string in the next
#: (C6: `keyword`/`ip` → list in 28 real columns, 7 of them mixing list and text).
_MULTI = esql_payload("FROM logs-* | KEEP host.name, host.ip, user.name", {
    "columns": [{"name": "host.name", "type": "keyword"}, {"name": "host.ip", "type": "ip"},
                {"name": "user.name", "type": "keyword"}],
    "values": [
        ["web-1", ["10.0.0.5", "fe80::1"], "alice"],
        ["web-2", "10.0.0.6", "bob"],
        ["db-1", None, "alice"],
        ["db-2", [], "carol"],
        ["web-3", ["10.0.0.5"], "dave"],
    ],
})


def test_o4_scalar_equals_on_a_list_column_fails_loudly_and_list_contains_answers():
    """O4: `WHERE "host.ip" = 'x'` must not answer a silent count — it errors (a list is not a
    string), and the error names the form that does answer. The same filter through
    `list_contains` returns the two rows that carry the address, including the one whose cell
    was a one-element list."""
    proc = _flag(_MULTI, 'SELECT count(*) AS n FROM data WHERE "host.ip" = \'10.0.0.5\'')
    assert_query_error(proc, "a scalar = on a list column answered")
    assert "list_contains" in proc.stderr, proc.stderr
    assert _ok(_flag(_MULTI, 'SELECT "host.name" FROM data WHERE list_contains("host.ip", '
                             "'10.0.0.5') ORDER BY 1")) == [
        {"host.name": "web-1"}, {"host.name": "web-3"}]


def test_o4_every_flagged_run_over_a_list_column_says_so_even_when_the_query_succeeds():
    """O4: `GROUP BY` and `count(DISTINCT)` over a list column group WHOLE lists and answer
    without an error, so the note is printed on every flagged run whose table has a list column
    — a query that never names it included — naming the list column(s) and the two forms. The
    scalar columns are not named as lists."""
    proc = _flag(_MULTI, "SELECT count(*) AS n FROM data")
    assert _ok(proc) == [{"n": 5}]
    assert "host.ip" in proc.stderr, proc.stderr
    assert "list_contains" in proc.stderr
    assert "unnest" in proc.stderr
    for scalar in ("host.name", "user.name"):
        assert scalar not in proc.stderr, f"the note named the scalar column {scalar!r} as a list"


def test_o4_the_note_names_every_list_column_and_is_absent_without_one():
    """O4, both directions on one shape: two list columns are both named; the same payload with
    its list columns dropped prints nothing at all (this payload is not truncated, so an empty
    stderr rules out every note)."""
    two = {"hdr": ["host.ip", "tags", "user"],
           "recs": [[["10.0.0.5"], ["a", "b"], "alice"], ["10.0.0.6", "c", "bob"]]}
    proc = _flag(two, "SELECT user FROM data ORDER BY user", rows="recs", names="hdr")
    assert _ok(proc) == [{"user": "alice"}, {"user": "bob"}]
    assert "host.ip" in proc.stderr, proc.stderr
    assert "tags" in proc.stderr, proc.stderr

    scalar_only = {"hdr": ["user"], "recs": [["alice"], ["bob"]]}
    control = _flag(scalar_only, "SELECT user FROM data ORDER BY user", rows="recs", names="hdr")
    assert _ok(control) == [{"user": "alice"}, {"user": "bob"}]
    assert control.stderr.strip() == "", control.stderr


#: List columns whose element type is not VARCHAR: a note or hint keyed on the spelling
#: `VARCHAR[]` misses every one of them. (id, cells, type, a lead's natural scalar `=`, the
#: `list_contains` form of it, the rows that form selects.)
_OTHER_LISTS = [
    ("bigint", [[22, 443], 80, [8080]], "BIGINT[]", "multi = 22", "list_contains(multi, 22)", 1),
    ("boolean", [[True], [False, True], False], "BOOLEAN[]", "multi = true",
     "list_contains(multi, true)", 2),
    ("double", [[0.5, 1.5], 2.5, [1.5]], "DOUBLE[]", "multi = 1.5", "list_contains(multi, 1.5)", 2),
]


@pytest.mark.parametrize(("cells", "typ", "scalar_eq", "contains", "n"),
                         [c[1:] for c in _OTHER_LISTS], ids=[c[0] for c in _OTHER_LISTS])
def test_o4_a_list_column_of_any_element_type_gets_the_note_and_the_list_clause(
        cells, typ, scalar_eq, contains, n):
    """O4 for a list of numbers or booleans, not only of strings: the column is a list column
    (a scalar cell wrapped), every flagged run over it names it with `list_contains` and
    `unnest`, a scalar `=` on it fails loudly with the list clause in the hint, and the
    `list_contains` form answers. The control is the same payload's scalar column alone: no note."""
    payload = {"hdr": ["host", "multi"], "recs": [[f"h{i}", c] for i, c in enumerate(cells)]}
    assert _schema(payload, rows="recs", names="hdr") == [("host", "VARCHAR"), ("multi", typ)]

    proc = _flag(payload, "SELECT count(*) AS n FROM data", rows="recs", names="hdr")
    assert _ok(proc) == [{"n": len(cells)}]
    assert "multi" in proc.stderr, proc.stderr
    assert "list_contains" in proc.stderr, proc.stderr
    assert "unnest" in proc.stderr, proc.stderr
    assert "host" not in proc.stderr, "the note named the scalar column as a list"

    failed = _flag(payload, f"SELECT count(*) AS n FROM data WHERE {scalar_eq}", rows="recs", names="hdr")
    assert_query_error(failed, f"a scalar = on a {typ} column answered")
    # The query holds no `list_contains`, so the word on stderr is the tool's hint.
    assert "list_contains" in failed.stderr, (
        f"the error hint on a {typ} column does not name the list form: {failed.stderr!r}")
    assert _ok(_flag(payload, f"SELECT count(*) AS n FROM data WHERE {contains}",
                     rows="recs", names="hdr")) == [{"n": n}]

    scalar_only = {"hdr": ["host"], "recs": [[f"h{i}"] for i in range(len(cells))]}
    control = _flag(scalar_only, "SELECT count(*) AS n FROM data", rows="recs", names="hdr")
    assert _ok(control) == [{"n": len(cells)}]
    assert control.stderr.strip() == "", control.stderr


def test_o4_a_scalar_cell_in_a_list_column_is_a_one_element_list_and_null_and_empty_survive():
    """O4: a non-list cell is wrapped as a one-element list, `null` stays NULL, `[]` stays
    empty — so `unnest` yields one row per address and `len` tells an empty list from a null."""
    assert _ok(_flag(_MULTI, 'SELECT "host.ip", len("host.ip") AS k FROM data')) == [
        {"host.ip": ["10.0.0.5", "fe80::1"], "k": 2},
        {"host.ip": ["10.0.0.6"], "k": 1},
        {"host.ip": None, "k": None},
        {"host.ip": [], "k": 0},
        {"host.ip": ["10.0.0.5"], "k": 1},
    ]
    assert _ok(_flag(_MULTI, 'SELECT ip, count(*) AS n FROM (SELECT unnest("host.ip") AS ip '
                             "FROM data) GROUP BY ip ORDER BY ip")) == [
        {"ip": "10.0.0.5", "n": 2}, {"ip": "10.0.0.6", "n": 1}, {"ip": "fe80::1", "n": 1}]


# ============================================= O5: payload bytes are never interpreted as SQL


_HOSTILE = 'x" VARCHAR); CREATE TABLE pwned(a INT); --'
_HOSTILE_CELL = "'); DROP TABLE data; --"


def _hostile_payload() -> dict:
    return {"hdr": [_HOSTILE, "ok"], "recs": [[_HOSTILE_CELL, 1], ["plain", 2]]}


def test_o5_a_hostile_name_loads_as_that_literal_name_and_creates_nothing():
    """O5: a declared name holding `"`, `;` and DDL reaches the statement only as an escaped
    identifier. It is ONE column with that exact name — in `DESCRIBE data` and as a result key —
    and the catalog holds `data` and nothing else: no `pwned`, no staging table left behind."""
    payload = _hostile_payload()
    assert _schema(payload, rows="recs", names="hdr") == [(_HOSTILE, "VARCHAR"), ("ok", "BIGINT")]
    assert _ok(_flag(payload, "SELECT * FROM data ORDER BY ok", rows="recs", names="hdr")) == [
        {_HOSTILE: _HOSTILE_CELL, "ok": 1}, {_HOSTILE: "plain", "ok": 2}]
    assert _ok(_flag(payload, "SELECT table_name FROM information_schema.tables",
                     rows="recs", names="hdr")) == [{"table_name": "data"}]
    assert _ok(_flag(payload, "SHOW TABLES", rows="recs", names="hdr")) == [{"name": "data"}]


#: Names holding a single quote — the delimiter of every SQL string literal, e.g. a
#: `columns={'<name>': '<type>'}` map — alone, beside a double quote, and shaped to close such
#: a literal and run DDL after it.
_SINGLE_QUOTED = [
    "o'brien",
    'x\'"); CREATE TABLE pwned(a INT); --',
    "a': 'VARCHAR'}); CREATE TABLE pwned2(a INT); --",
]


def _ident(name: str) -> str:
    """`name` as a double-quoted SQL identifier — the lead's own spelling of it."""
    return '"' + name.replace('"', '""') + '"'


def test_o5_a_name_holding_a_single_quote_loads_as_that_literal_name_and_creates_nothing():
    """O5 for the OTHER quote: a name holding `'` — alone, with `"`, and crafted to break out of
    a single-quoted literal — reaches no statement as text. Each is one column with exactly that
    name (in `DESCRIBE data` and as a result key), each can be selected and filtered on by its
    quoted name, and the catalog holds `data` and nothing else."""
    payload = {"hdr": [*_SINGLE_QUOTED, "ok"],
               "recs": [["v0", "v1", "v2", 1], ["w0", "w1", "w2", 2]]}
    assert _schema(payload, rows="recs", names="hdr") == [
        *((n, "VARCHAR") for n in _SINGLE_QUOTED), ("ok", "BIGINT")]
    picked = ", ".join(_ident(n) for n in _SINGLE_QUOTED)
    for i, name in enumerate(_SINGLE_QUOTED):
        assert _ok(_flag(payload, f"SELECT {picked}, ok FROM data WHERE {_ident(name)} = 'w{i}'",
                         rows="recs", names="hdr")) == [
            {**{n: f"w{j}" for j, n in enumerate(_SINGLE_QUOTED)}, "ok": 2}]
    assert _ok(_flag(payload, "SELECT table_name FROM information_schema.tables",
                     rows="recs", names="hdr")) == [{"table_name": "data"}]


@pytest.mark.parametrize("hostile", [
    "SELECT * FROM read_json('/etc/hostname')",
    "SELECT * FROM read_text('/etc/hostname')",
    "SELECT * FROM read_csv('/etc/hostname')",
    "SET enable_external_access=true",
])
def test_o5_the_sandbox_is_locked_before_the_lead_s_query_runs(hostile):
    """O5: the flagged load reads the payload itself, and the lock falls AFTER that load and
    BEFORE the lead's SQL — a file read or an unlock attempt in the query is refused. The
    paired control: the same flagged payload answers a plain query in the same process shape."""
    payload = _hostile_payload()
    assert_query_error(_flag(payload, hostile, rows="recs", names="hdr"),
                       "a flagged run let the query reach the filesystem or the configuration")
    assert _ok(_flag(payload, _SQL, rows="recs", names="hdr")) == [{"n": 2}]


# ================================================ O6: unflagged behaves as today, and says so


#: The same ES|QL shape in each typing `read_json_auto` gives `values` (C1). A note keyed on
#: one type spelling (`JSON[][]`) would miss the others.
_TYPINGS = {
    "VARCHAR[][]": {"columns": [{"name": "host.name", "type": "keyword"},
                                {"name": "user.name", "type": "keyword"}],
                    "values": [["web-1", "alice"], ["db-1", "bob"]]},
    "JSON[][]": {"columns": _ESQL["columns"], "values": _ESQL["values"]},
    "BIGINT[][]": {"columns": [{"name": "a", "type": "long"}, {"name": "b", "type": "long"}],
                   "values": [[1, 2], [3, 4]]},
    "TIMESTAMP[][]": {"columns": [{"name": "@timestamp", "type": "date"}],
                      "values": [["2026-08-07T11:32:52.000Z"], ["2026-08-07T11:33:10.000Z"]]},
    "DOUBLE[][]": {"columns": [{"name": "ratio", "type": "double"}, {"name": "score", "type": "double"}],
                   "values": [[1.5, 2.5], [3.5, 4.5]]},
    "BOOLEAN[][]": {"columns": [{"name": "ok", "type": "boolean"}, {"name": "seen", "type": "boolean"}],
                    "values": [[True, False], [False, True]]},
}


@pytest.mark.parametrize("typing", list(_TYPINGS))
def test_o6_an_unflagged_count_over_positional_rows_names_the_flags(typing):
    """O6 / C4: unflagged, `SELECT count(*) FROM data` over an ES|QL payload answers 1 — one
    object, one row — with exit 0 and no error. That answer stays (unflagged is unchanged), and
    the run now says on stderr how to declare the rows. The first assertion pins the premise:
    this payload really is loaded in the typing the case is named for."""
    payload = esql_payload(_ESQL_QUERY, _TYPINGS[typing])
    described = {r["column_name"]: r["column_type"] for r in _ok(_plain(payload, "DESCRIBE data"))}
    assert described["values"] == typing, f"premise: read_json_auto typed values {described}"

    proc = _plain(payload, "SELECT count(*) AS n FROM data")
    assert _ok(proc) == [{"n": 1}]
    assert "--rows values --names columns" in proc.stderr, proc.stderr


def test_o6_an_unflagged_error_over_positional_rows_names_the_flags_and_no_positions():
    """O6: every run, the failing ones included — and the positional recipe is gone from the
    hint: no `Positions:` map, no `->>'$'` form to copy."""
    proc = _plain(_ESQL, "SELECT nope FROM data")
    assert_query_error(proc, "a missing column was not an error")
    assert "--rows values --names columns" in proc.stderr, proc.stderr
    # The query holds no arrow, so any `->>` on stderr is the tool's own text.
    assert "Positions:" not in proc.stderr
    assert "->>" not in proc.stderr, f"the unflagged hint still teaches the positional recipe: {proc.stderr!r}"


@pytest.mark.parametrize(("payload", "note"), [
    ({"fields": ["host", "n"], "rows": [["web-1", 1], ["db-1", 2]], "count": 2},
     "--rows rows --names fields"),
    ({"matrix": [[1, 2], [3, 4]], "hdr": ["a", "b"]}, "--rows matrix --names hdr"),
    ({"cols": [{"name": "a"}, {"name": "b"}], "data_rows": [["x", 1]]},
     "--rows data_rows --names cols"),
], ids=["splunk", "bare-matrix", "renamed-esql"])
def test_o6_the_note_detects_by_shape_and_names_this_payloads_own_keys(payload, note):
    """O6: detection is by SHAPE — a top-level list of lists — never by the key names ES|QL
    happens to use. Each payload names its own keys in the note, and the names key is the one
    whose length matches the rows (a list of strings, or of `{name: …}` objects). None of them
    is ES|QL's `values`/`columns`."""
    proc = _plain(payload, "SELECT 1 AS one")
    assert _ok(proc) == [{"one": 1}]
    assert note in proc.stderr, proc.stderr
    assert "--rows values" not in proc.stderr
    assert "--names columns" not in proc.stderr


@pytest.mark.parametrize("slot", ["rows", "names"])
@pytest.mark.parametrize("key", ["my rows", "$(id)", "a;b", "x.y", "r`id`", "my names", "-v"])
def test_o6_a_key_outside_the_safe_set_is_not_echoed_into_the_command(key, slot):
    """O6 (security): the note hands the lead a command to copy, so a payload key reaches it
    only when it matches `[A-Za-z0-9_@][A-Za-z0-9_@-]*` — the rows key AND the names key. A key
    with a space, `$(`, `;`, `.`, a backtick, or a LEADING dash (`-v` would read as a flag in the
    copied command) is not echoed at all; the note still says to declare the rows,
    and the SAFE key beside it is still echoed. The control is both keys safe on the same shape,
    and both echoed."""
    payload = {key: [[1, 2]], "hdr": ["a", "b"]} if slot == "rows" else {"recs": [[1, 2]], key: ["a", "b"]}
    proc = _plain(payload, "SELECT 1 AS one")
    assert _ok(proc) == [{"one": 1}]
    assert "--rows" in proc.stderr, proc.stderr
    assert "--names" in proc.stderr, proc.stderr
    assert key not in proc.stderr, f"an unsafe payload key was echoed into the note: {proc.stderr!r}"
    safe_beside = "--names hdr" if slot == "rows" else "--rows recs"
    assert safe_beside in proc.stderr, f"the safe key beside it was not echoed: {proc.stderr!r}"

    safe = _plain({"r_ok-1@x": [[1, 2]], "hdr": ["a", "b"]}, "SELECT 1 AS one")
    assert _ok(safe) == [{"one": 1}]
    assert "--rows r_ok-1@x --names hdr" in safe.stderr, safe.stderr


_NOTE_DECLARATION = re.compile(r"--rows (\S+) --names (\S+)")


@pytest.mark.parametrize(("payload", "declared", "sql", "rows"), [
    ({"tags": ["a", "b", "c"], "fields": ["host", "n"], "rows": [["web-1", 1], ["db-1", 2]]},
     ("rows", "fields"), "SELECT host FROM data WHERE n = 2", [{"host": "db-1"}]),
    ({"schema": [{"name": "x"}, {"name": "y"}, {"name": "z"}], "cols": [{"name": "host"}, {"name": "n"}],
      "data_rows": [["web-1", 1], ["db-1", 2]]},
     ("data_rows", "cols"), "SELECT host FROM data WHERE n = 1", [{"host": "web-1"}]),
], ids=["string-lists", "name-object-lists"])
def test_o6_the_names_key_is_the_candidate_whose_length_matches_the_rows(payload, declared, sql, rows):
    """O6: `<names-key>` is the top-level list of names whose LENGTH equals the rows' width — not
    merely the first list of names in key order. Here a list of the wrong length comes first,
    so a note naming the first candidate names the wrong key. The declaration taken out of
    stderr, run as printed, answers."""
    proc = _plain(payload, "SELECT 1 AS one")
    assert _ok(proc) == [{"one": 1}]
    found = _NOTE_DECLARATION.search(proc.stderr)
    assert found, f"no declaration on stderr: {proc.stderr!r}"
    assert found.groups() == declared, proc.stderr
    printed = ("--rows", found.group(1), "--names", found.group(2))
    assert _ok(run_sql_warm(*printed, sql, stdin=json.dumps(payload))) == rows


@pytest.mark.parametrize(("payload", "sql", "rows"), [
    ({"total": 2, "returned": 2, "truncated": False, "hits": [{"u": "a"}, {"u": "b"}]},
     "SELECT count(*) AS n FROM (SELECT unnest(hits) h FROM data)", [{"n": 2}]),
    ({"host": "web-1", "owner": "team.platform"}, "SELECT owner FROM data",
     [{"owner": "team.platform"}]),
    ([{"u": "a"}, {"u": "b"}], "SELECT count(*) AS n FROM data", [{"n": 2}]),
    ({"tags": ["a", "b"], "n": 1}, "SELECT n FROM data", [{"n": 1}]),
], ids=["hits", "flat", "bare-array", "flat-with-a-list"])
def test_o6_a_payload_without_positional_rows_gets_no_note(payload, sql, rows):
    """O6's control: hits, flat and array payloads behave exactly as today, with nothing new on
    stderr — including a flat object holding a list of SCALARS, which is not a list of lists."""
    proc = _plain(payload, sql)
    assert _ok(proc) == rows
    assert proc.stderr.strip() == "", proc.stderr


def test_o6_the_flagged_run_prints_no_declare_note():
    """O6's other control: once the rows are declared, the note that asks for the declaration
    is gone — the flagged run over the same ES|QL payload prints nothing on stderr."""
    unflagged = _plain(_ESQL, _SQL)
    assert "--rows" in unflagged.stderr, "premise: the unflagged run carries the note"
    flagged = _flag(_ESQL, _SQL)
    assert _ok(flagged) == [{"n": 5}]
    assert flagged.stderr.strip() == "", flagged.stderr


# ============================================== M3: the flagged error hint is about THIS table


def test_m3_a_flagged_query_error_lists_the_declared_columns_with_their_types():
    """M3 (O1): under the flags the hits/flat idioms do not apply; the hint lists the declared
    columns with their types — what the lead needs to fix a name or a comparison — and no
    `unnest(hits)` skeleton."""
    payload = {"hdr": ["failed", "source.ip", "ok"], "recs": [[1, "a", True]]}
    proc = _flag(payload, "SELECT nope FROM data", rows="recs", names="hdr")
    assert_query_error(proc, "a missing column was not an error")
    for fragment in ("failed", "source.ip", "ok", "BIGINT", "VARCHAR", "BOOLEAN"):
        assert fragment in proc.stderr, f"{fragment!r} missing from the flagged hint: {proc.stderr!r}"
    assert "unnest(hits)" not in proc.stderr


def test_m3_a_json_column_compared_as_text_gets_the_unpack_form_and_it_runs():
    """M3 (O1/O2): a mixed-kind column is JSON, and `= 'text'` on it fails `Malformed JSON` —
    loudly. The hint names the unpacking form, and that form, written for this column, answers."""
    payload = {"hdr": ["host", "n"], "recs": [["web-1", 1], [7, 2], ["web-1", 3]]}
    assert _schema(payload, rows="recs", names="hdr") == [("host", "JSON"), ("n", "BIGINT")]
    proc = _flag(payload, "SELECT count(*) AS n FROM data WHERE host = 'web-1'", rows="recs", names="hdr")
    assert_query_error(proc, "a text comparison on a JSON column answered")
    assert "->>'$'" in proc.stderr or "AS VARCHAR" in proc.stderr, proc.stderr
    assert _ok(_flag(payload, "SELECT count(*) AS n FROM data WHERE (host->>'$') = 'web-1'",
                     rows="recs", names="hdr")) == [{"n": 2}]


# ============================ O8: every reduction example is correct for any payload shape


#: Every model-facing tree: the runtime, the skills, the scripts (tools and adapters), the
#: learning loop's prompts, the hooks, the lesson corpora, and the top-level agent files.
_MODEL_FACING = ("runtime", "skills", "scripts", "learning", "hooks", "bin",
                 "lessons", "lessons-actor", "lessons-environment", "lessons-questioner")
_COUNT_OVER_DATA = re.compile(r"select\s+count\s*\(\s*\*\s*\)(\s+as\s+\w+)?\s+from\s+data\b",
                              re.IGNORECASE)


def _model_facing_files() -> list[Path]:
    files = [DEFENDER / "SKILL.md", DEFENDER / "agents.py"]
    for root in _MODEL_FACING:
        base = DEFENDER / root
        if base.is_dir():
            files += [p for p in base.rglob("*")
                      if p.suffix in (".py", ".md", ".yaml", ".yml", ".txt")
                      and "__pycache__" not in p.parts and "runs" not in p.parts]
    return sorted(p for p in files if p.is_file())


def test_o8_no_model_facing_text_offers_a_count_over_the_whole_payload():
    """O8 / C4: `SELECT count(*) FROM data` answers 1 on every object payload — ES|QL and the
    search-hits envelope alike — so offered as "the" reduction it is wrong on the shapes a lead
    is most often handed. No model-facing file may offer it. The positive control proves the
    scan reads the two sites that offered it (C5) and that its pattern matches their spelling."""
    files = _model_facing_files()
    rel = {str(p.relative_to(DEFENDER)) for p in files}
    assert {"runtime/tools/_deps.py", "scripts/gather_tools/payload_view.py",
            "skills/gather/defender-sql.md"} <= rel, "the census lost a surface it must read"
    assert _COUNT_OVER_DATA.search('reducer = f\'{sql_shim} "SELECT count(*) FROM data"\'')
    assert _COUNT_OVER_DATA.search("defender-sql 'select COUNT(*) as n from data'")
    offending = {str(p.relative_to(DEFENDER)): m.group(0) for p in files
                 if (m := _COUNT_OVER_DATA.search(read_text_utf8(p)))}
    assert not offending, f"a model-facing surface offers a whole-payload count: {offending}"


# ================================ O9: every lead-facing text teaches the flagged form, and runs


_POSITIONAL_RECIPE = re.compile(r"v\s*\[\s*\d+\s*\]\s*->>")
_UNNEST_VALUES = re.compile(r"unnest\s*\(\s*(data\.)?values\s*\)", re.IGNORECASE)


def test_o9_help_teaches_the_flags_and_no_positional_recipe():
    """O9: `--help` is lead-facing text. It names both flags, shows a flagged example beside the
    hits one, and carries neither `v[N]->>` nor `unnest(values)`."""
    proc = run_sql_py("--help")
    assert proc.returncode == EXIT_OK, proc.stderr
    printed = " ".join((proc.stdout + proc.stderr).split())
    assert "--rows" in printed, printed
    assert "--names" in printed, printed
    assert re.search(r"defender-sql --rows[ =]\S+ --names[ =]\S+", printed), (
        f"--help shows no flagged invocation: {printed!r}")
    assert "unnest(hits)" in printed, "the hits example left --help"
    assert not _POSITIONAL_RECIPE.search(printed), printed
    assert not _UNNEST_VALUES.search(printed), printed


def test_o9_the_misbound_arrow_refusal_teaches_a_generic_json_column_not_a_position():
    """O9: `_MISBOUND`'s example becomes `(col->>'$') = '<value>'` — rendered on a flagged JSON
    column and on the unflagged ES|QL payload alike, it carries an arrow form but no `v[N]`.
    (The refusal prints the tool's own text and hint, never an echo of the query, so the
    positions in the unflagged query below cannot leak into what is asserted.) The paired
    control: parenthesised, the flagged filter runs."""
    json_col = {"hdr": ["code", "n"], "recs": [["4625", 1], [4624, 2]]}
    flagged = _flag(json_col, "SELECT count(*) AS n FROM data WHERE '4625' = code->>'$'",
                    rows="recs", names="hdr")
    unflagged = _plain(_ESQL, "SELECT count(*) AS n FROM (SELECT unnest(values) v FROM data) "
                              "WHERE v[1]->>'$' = '412' AND v[2]->>'$' = '203.0.113.7'")
    for proc in (flagged, unflagged):
        assert_query_error(proc, "a misbound arrow ran")
        assert "binds more loosely than" in proc.stderr, proc.stderr
        assert "->>'$'" in proc.stderr, proc.stderr
        assert not re.search(r"v\[\d+\]", proc.stderr), (
            f"the refusal still teaches a positional example: {proc.stderr!r}")
    assert _ok(_flag(json_col, "SELECT count(*) AS n FROM data WHERE '4625' = (code->>'$')",
                     rows="recs", names="hdr")) == [{"n": 1}]


def test_o9_the_doc_carries_no_positional_recipe_and_names_the_flags():
    """O9: `defender-sql.md` teaches the flagged form for positional rows — both flags, the
    ES|QL declaration a lead types (`--rows values --names columns`) and list columns
    (`list_contains`) — and the `v[N]->>'$'` / `unnest(values)` recipe is gone from it."""
    doc = read_text_utf8(_DOC)
    assert not _POSITIONAL_RECIPE.search(doc), "the doc still teaches `v[N]->>`"
    assert not _UNNEST_VALUES.search(doc), "the doc still teaches `unnest(values)`"
    assert re.search(r"--rows[ =]values", doc), "the doc does not show the ES|QL declaration"
    assert re.search(r"--names[ =]columns", doc), "the doc does not show the ES|QL declaration"
    assert "list_contains" in doc, "the doc does not teach list columns"


@pytest.mark.parametrize("surface", ["skills/connect/adapter.md", "learning/leads/lead_pitfalls.md"])
def test_o9_the_adapter_contract_and_the_pitfalls_curator_name_the_flagged_form(surface):
    """O9: the adapter contract's rung 2 (how a positional-row payload is queried) and the
    curator that writes `defender-sql.md`'s pitfalls (so it does not re-record the dead recipe
    as current) both name `--rows`, and neither teaches the positional recipe."""
    text = read_text_utf8(DEFENDER / surface)
    assert "--rows" in text, f"{surface} does not name the flagged form"
    assert not _POSITIONAL_RECIPE.search(text), f"{surface} teaches `v[N]->>`"
    assert not _UNNEST_VALUES.search(text), f"{surface} teaches `unnest(values)`"


# ======================================== O10: the largest source payload loads well in time


def _large_payload(n_rows: int = 10_000, n_cols: int = 20) -> dict:
    """ES|QL's row ceiling, 20 columns wide: one ISO-time column, one multi-valued `host.ip`
    (list in most rows, a bare string in some), the rest numbers and text."""
    columns = [{"name": "@timestamp", "type": "date"}, {"name": "host.ip", "type": "ip"}]
    columns += [{"name": f"f{j}", "type": "long" if j % 2 else "keyword"} for j in range(n_cols - 2)]
    values = []
    for i in range(n_rows):
        ts = f"2026-08-07T{(i // 3600) % 24:02d}:{(i // 60) % 60:02d}:{i % 60:02d}.{i % 1000:03d}Z"
        ips = f"10.0.{i % 250}.{i % 7}" if i % 5 == 0 else [f"10.0.{i % 250}.{i % 7}", "fe80::1"]
        values.append([ts, ips, *[(i * j) if j % 2 else f"v{i % 97}-{j}" for j in range(n_cols - 2)]])
    return esql_payload("FROM logs-* | LIMIT 10000", {"columns": columns, "values": values})


def test_o10_a_ten_thousand_by_twenty_flagged_load_is_well_inside_the_bash_timeout():
    """O10 / C17: the bash lane kills a command at 120 s; a row-by-row insert measured 63 s for
    this size. The flagged load of ES|QL's largest result — with a list column and an ISO-time
    column — must finish under 5 s, spawn included, and answer correctly: every row counted,
    the list column a list, the time strings the source's own text."""
    payload = _large_payload()
    last_ts = max(row[0] for row in payload["values"])
    text = json.dumps(payload)
    started = time.monotonic()
    proc = run_sql_py("--rows", "values", "--names", "columns",
                      'SELECT count(*) AS n, max("@timestamp") AS last, '
                      'sum(len("host.ip")) AS ips FROM data', stdin=text)
    elapsed = time.monotonic() - started
    assert _ok(proc) == [{"n": 10_000, "last": last_ts, "ips": 2 * 10_000 - 10_000 // 5}]
    assert elapsed < 5.0, f"the flagged 10,000 x 20 load took {elapsed:.2f}s"


# ===================== R1: the declare note is decided from the PARSED payload, not duckdb's types


_EMPTY_ESQL = {"columns": [{"name": "failed", "type": "long"}], "values": [], "row_count": 0}


@pytest.mark.parametrize(("payload", "declared"), [
    (_EMPTY_ESQL, ("values", "columns")),
    ({"fields": ["host", "n"], "rows": [], "count": 0}, ("rows", "fields")),
], ids=["esql", "splunk"])
def test_r1_an_empty_positional_result_gets_the_note_and_its_declaration_answers_zero(payload, declared):
    """R1: an ES|QL query that matched nothing still hands back `values: []` beside its
    `columns`. Unflagged, `count(*)` answers 1 — the one object — which reads as "one match", so
    the note fires on an EMPTY list of rows too, when a sibling holds the names. The
    declaration taken out of stderr, run as printed, answers the truth: 0."""
    proc = _plain(payload, _SQL)
    assert _ok(proc) == [{"n": 1}]
    found = _NOTE_DECLARATION.search(proc.stderr)
    assert found, f"an empty positional result printed no declaration: {proc.stderr!r}"
    assert found.groups() == declared, proc.stderr
    printed = ("--rows", found.group(1), "--names", found.group(2))
    assert _ok(run_sql_warm(*printed, _SQL, stdin=json.dumps(payload))) == [{"n": 0}]


def test_r1_a_non_empty_list_of_rows_fires_even_with_no_names_beside_it():
    """R1: rows alone are enough to say "declare them" — the names slot stays generic."""
    proc = _plain({"matrix": [[1, 2], [3, 4]]}, _SQL)
    assert _ok(proc) == [{"n": 1}]
    assert "--rows matrix --names <names-key>" in proc.stderr, proc.stderr


_ESQL_A = {"columns": [{"name": "a", "type": "long"}], "values": [[1], [2]]}
_ESQL_B = {"columns": [{"name": "a", "type": "long"}], "values": [[3]]}


@pytest.mark.parametrize(("stdin", "n"), [
    (json.dumps([_ESQL_A, _ESQL_B]), 2),
    (json.dumps(_ESQL_A) + "\n" + json.dumps(_ESQL_B) + "\n", 2),
    (json.dumps({"tags": []}), 1),
    (json.dumps({"values": [], "columns": []}), 1),
    (json.dumps({"values": [], "ids": [1, 2]}), 1),
    (json.dumps({"values": [[1], 2], "hdr": ["a"]}), 1),
], ids=["top-level-array", "ndjson", "empty-list-alone", "empty-names-beside",
        "numbers-beside", "not-every-element-a-list"])
def test_r1_no_note_where_the_payload_is_not_one_object_holding_positional_rows(stdin, n):
    """R1's controls. The note fires only for ONE JSON document whose top level is an object
    with a key holding a list of lists. A top-level array or NDJSON of ES|QL-shaped objects is
    one row PER object — `count(*)` answers 2 here, so "count(*) answers 1" would be a false
    claim — and an empty list fires only beside a non-empty list of names. A list that is not
    all lists is not rows. None of these prints anything on stderr."""
    proc = run_sql_warm(_SQL, stdin=stdin)
    assert _ok(proc) == [{"n": n}]
    assert "--rows" not in proc.stderr, proc.stderr
    assert "answers 1" not in proc.stderr, proc.stderr
    assert proc.stderr.strip() == "", proc.stderr


def test_r1_a_key_with_an_inner_dash_is_still_echoed():
    """R1's echo rule forbids only a LEADING dash: `my-rows` / `my-names` are echoed as-is."""
    proc = _plain({"my-rows": [[1, 2]], "my-names": ["a", "b"]}, "SELECT 1 AS one")
    assert _ok(proc) == [{"one": 1}]
    assert "--rows my-rows --names my-names" in proc.stderr, proc.stderr


def test_r1_an_unflagged_error_on_positional_rows_names_the_declaration_not_the_flat_idiom():
    """R1: on a positional payload the flat/array idiom — "the keys ARE `data`'s columns;
    `SELECT * FROM data`" — is the wrong advice (its only rows are the envelope); the error
    names the declaration instead. The flat idiom still answers a genuinely flat payload."""
    proc = _plain(_ESQL, "SELECT nope FROM data")
    assert_query_error(proc, "a missing column was not an error")
    assert "--rows values --names columns" in proc.stderr, proc.stderr
    assert "flat/array" not in proc.stderr, proc.stderr
    assert "SELECT * FROM data" not in proc.stderr, proc.stderr

    flat = _plain({"host": "web-1", "owner": "team.platform"}, "SELECT nope FROM data")
    assert_query_error(flat, "a missing column was not an error")
    assert "SELECT * FROM data" in flat.stderr, flat.stderr
    assert "--rows" not in flat.stderr, flat.stderr


# ============================== R2: the flagged load is one boundary — nothing escapes as a traceback


@pytest.mark.parametrize(("bad", "good"), [
    ("b\ud800", "b"),
    (["b\ud800", "c"], ["b", "c"]),
    ({"k": "b\ud800"}, {"k": "b"}),
    ("\udfff", 7),
], ids=["string-cell", "list-element", "object-value", "json-column"])
def test_r2_a_lone_surrogate_in_a_cell_is_an_input_error_not_a_traceback(bad, good):
    """R2: a lone UTF-16 surrogate (`"\\ud800"` as a JSON escape) parses in Python but cannot be
    loaded as text. Under the flag that is the payload's defect, refused as input (exit 2) with
    the tool's own message — never a traceback out of the load. The same payload with the cell
    fixed loads."""
    def payload(cell) -> str:
        return json.dumps({"hdr": ["user", "x"], "recs": [["alice", 1], ["bob", cell]]})
    text = payload(bad)
    assert "\\ud" in text, "premise: the surrogate travels as a JSON escape"
    assert text.isascii(), "premise: the payload text is plain ASCII"
    proc = run_sql_warm("--rows", "recs", "--names", "hdr", _SQL, stdin=text)
    _refused(proc, EXIT_INPUT_ERROR, "load")
    assert _ok(run_sql_warm("--rows", "recs", "--names", "hdr", _SQL, stdin=payload(good))) == [{"n": 2}]


def test_r2_a_valid_surrogate_pair_is_not_a_defect():
    """R2's control: an escaped surrogate PAIR is one ordinary character (😀), and it loads and
    round-trips — the refusal above is about a LONE surrogate, not about escapes."""
    text = json.dumps({"hdr": ["user"], "recs": [["\U0001F600"], ["bob"]]})
    assert "\\ud83d\\ude00" in text, "premise: the pair travels escaped"
    assert _ok(run_sql_warm("--rows", "recs", "--names", "hdr", "SELECT user FROM data ORDER BY 1",
                          stdin=text)) == [{"user": "bob"}, {"user": "\U0001F600"}]


# ======================================================== R3: JSON columns say what they hold


_JSON_NUMBERS = {"hdr": ["event.code"], "recs": [[412], [10], [9], ["n/a"]]}


def _call(text: str, fn: str) -> str:
    """The first `fn(...)` call spelled in `text`, parentheses balanced."""
    start = text.find(f"{fn}(")
    assert start >= 0, f"no `{fn}(` in: {text!r}"
    depth = 0
    for i in range(start + len(fn), len(text)):
        depth += {"(": 1, ")": -1}.get(text[i], 0)
        if depth == 0:
            return text[start:i + 1]
    raise AssertionError(f"unbalanced `{fn}(` in: {text!r}")


def _on_column(recipe: str, column: str) -> str:
    """`recipe` with its JSON operand — whatever stands before its `->>` (`col`, `<col>`, or the
    column itself) — made `column`, double-quoted."""
    quoted = '"' + column.replace('"', '""') + '"'
    bound, count = re.subn(r"(\(\s*)[^()]*?(\s*->>)", lambda m: f"{m.group(1)}{quoted}{m.group(2)}",
                           recipe, count=1)
    assert count == 1, f"the recipe has no `->>` to bind a column to: {recipe!r}"
    return bound


@pytest.mark.parametrize("sql", [_SQL, "SELECT nope FROM data"], ids=["success", "error"])
def test_r3_every_flagged_run_over_a_json_column_says_it_holds_json_and_how_to_cast_it(sql):
    """R3: a column mixing numbers and text is JSON, and `->>'$'` on it is TEXT — compared or
    summed as text, `'412' < '9'`. Every flagged run over such a table, success or error, names
    the JSON column(s) on stderr, says `->>'$'` gives text, and hands over a `TRY_CAST` recipe.
    That recipe, bound to this column and run, orders the numbers AS numbers: max 412, and two
    rows above 9 — the text `n/a` a NULL, not an error."""
    proc = run_sql_warm("--rows", "recs", "--names", "hdr", sql, stdin=json.dumps(_JSON_NUMBERS))
    assert proc.returncode in (EXIT_OK, EXIT_QUERY_ERROR), proc.stderr
    assert "Traceback" not in proc.stderr
    assert "event.code" in proc.stderr, proc.stderr
    assert "->>'$'" in proc.stderr, proc.stderr
    assert re.search(r"\btext\b", proc.stderr, re.IGNORECASE), proc.stderr
    recipe = _on_column(_call(proc.stderr, "TRY_CAST"), "event.code")
    assert _ok(_flag(_JSON_NUMBERS, f"SELECT max({recipe}) AS m FROM data",
                     rows="recs", names="hdr")) == [{"m": 412}]
    assert _ok(_flag(_JSON_NUMBERS, f"SELECT count(*) AS n FROM data WHERE {recipe} > 9",
                     rows="recs", names="hdr")) == [{"n": 2}]


def test_r3_the_json_note_names_every_json_column_and_only_those():
    """R3: two JSON columns (mixed kinds; objects; a list of mixed kinds) are all named; the
    number column beside them is not. The control is the number column alone: no note at all."""
    payload = {"hdr": ["event.code", "detail", "tags", "bytes"],
               "recs": [[412, {"a": 1}, ["x", 5], 1], ["n/a", {"b": 2}, "c", 2]]}
    assert _schema(payload, rows="recs", names="hdr") == [
        ("event.code", "JSON"), ("detail", "JSON"), ("tags", "JSON"), ("bytes", "BIGINT")]
    proc = _flag(payload, _SQL, rows="recs", names="hdr")
    assert _ok(proc) == [{"n": 2}]
    for json_column in ("event.code", "detail", "tags"):
        assert json_column in proc.stderr, f"the JSON column {json_column!r} was not named"
    assert "bytes" not in proc.stderr, "a BIGINT column was named as JSON"
    assert "TRY_CAST" in proc.stderr, proc.stderr

    control = _flag({"hdr": ["bytes"], "recs": [[1], [2]]}, _SQL, rows="recs", names="hdr")
    assert _ok(control) == [{"n": 2}]
    assert control.stderr.strip() == "", control.stderr


#: Every list type the rule produces: (cells, the column type, a value one of the lists holds,
#: how many rows hold it).
_LIST_TYPES = [
    ([["10.0.0.5", "fe80::1"], "10.0.0.6"], "VARCHAR[]", "10.0.0.5", 1),
    ([[22, 443], 80, [22]], "BIGINT[]", 22, 2),
    ([[0.5, 1.5], 2.5], "DOUBLE[]", 1.5, 1),
    ([[True], [False, True], False], "BOOLEAN[]", True, 2),
    ([[2**64, 1], [2]], "HUGEINT[]", 2**64, 1),
]


def _sql_literal(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return f"'{value}'" if isinstance(value, str) else str(value)


@pytest.mark.parametrize(("cells", "typ", "value", "n"), _LIST_TYPES,
                         ids=[t for _, t, _, _ in _LIST_TYPES])
def test_r3_the_notes_list_contains_recipe_runs_on_every_list_type(cells, typ, value, n):
    """R3: the O4 note's `list_contains` recipe is copied by the lead onto whatever list column
    it has. Taken out of stderr, with a real value put in its placeholder (inside the recipe's
    own quotes if it has them), it runs on every list type the rule produces and finds the
    rows that hold the value."""
    payload = {"hdr": ["multi"], "recs": [[c] for c in cells]}
    assert _schema(payload, rows="recs", names="hdr") == [("multi", typ)]
    proc = _flag(payload, _SQL, rows="recs", names="hdr")
    assert _ok(proc) == [{"n": len(cells)}]
    recipe = _call(proc.stderr, "list_contains")
    placeholder = re.search(r"'?<[^>]+>'?", recipe)
    assert placeholder, f"the recipe has no value placeholder: {recipe!r}"
    text = placeholder.group(0)
    literal = (f"'{_sql_literal(value).strip(chr(39))}'" if text.startswith("'") and text.endswith("'")
               else _sql_literal(value))
    bound = recipe.replace(text, literal, 1)
    assert _ok(_flag(payload, f"SELECT count(*) AS n FROM data WHERE {bound}",
                     rows="recs", names="hdr")) == [{"n": n}], bound


def test_r3_the_doc_says_a_json_columns_unpacked_value_is_text_and_to_cast_it():
    """R3: `defender-sql.md`'s guidance for JSON columns says `->>'$'` returns TEXT and to cast
    before comparing, sorting or summing a number. Read per paragraph and per bullet, so the
    words must sit together in the JSON-column guidance rather than anywhere in the doc."""
    doc = read_text_utf8(_DOC)
    blocks = [b for b in re.split(r"\n\s*\n|\n(?=\s*[-*] )", doc) if "JSON" in b and "->>" in b]
    assert blocks, "the doc has no JSON-column guidance with `->>`"
    assert any(re.search(r"\bTRY_CAST\s*\(|\bCAST\s*\(", b) and re.search(r"\btext\b", b, re.I)
               for b in blocks), f"no JSON-column guidance says `->>` is text and to cast: {blocks}"

