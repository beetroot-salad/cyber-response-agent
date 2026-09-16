"""The SQL idioms a gather lead is taught must actually RUN, through the real command.

`skills/gather/SKILL.md` sends every investigating lead to `defender-sql.md` before it
writes SQL, and `defender-sql.md` teaches one binding per payload shape. A binding that
does not run is not a documentation bug — it is a lead that burns its turns on Binder
Errors and then reports an absence it never established.

These guards were written for a judge pipeline that no longer exists and were deleted
whole with it (`e9e11a48`, #922); 20 of the 23 were never about the judge at all, they
were about `scripts/gather_tools/sql.py`, which is still the lead's tool. This file is
those 20, restored against the surfaces that survive and re-driven as a REAL subprocess:
`sys.executable sql.py '<query>'` with the payload on stdin is what a lead's
`cat payload.json | defender-sql '...'` actually does, so the exit code, the stdout JSON
and the stderr hint are all observed the way the lead observes them. `test_sql.py` keeps
the in-process harness for the internals (sandbox, column disambiguation); nothing here
monkeypatches anything.

The shapes are the ones a gather_raw payload actually comes in, from the corpus survey
that motivated the tool:

    {index, total, returned, truncated, hits}   -> unnest(hits) yields a STRUCT
    {columns, values, row_count}  (ES|QL)       -> unnest(values) yields a POSITIONAL array
    flat object                                 -> one row, its keys are the columns
    bare array                                  -> one row per element
    empty / not JSON                            -> input error (exit 2), NOT an empty result

Skipped when duckdb is absent: it lives in the `runtime` extra, not `dev`/CI, which is
the same condition the deleted file skipped on.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys

import pytest

from defender.scripts.adapters.elastic_adapter import esql_payload
from defender.tests._by_path import DEFENDER

pytest.importorskip("duckdb")

_SQL_PY = DEFENDER / "scripts" / "gather_tools" / "sql.py"
_DOC = DEFENDER / "skills" / "gather" / "defender-sql.md"

#: The real ES|QL payload a lead was handed in a checked-in scenario run: `columns`
#: `failed:long, source.ip:ip`, three POSITIONAL rows, `row_count: 3`. Hand-writing this
#: shape is what let it drift once already (see `test_the_adapter_emits_the_shape_this_fixture_has`).
_REAL_ESQL = (
    DEFENDER / "evals" / "scenarios_lead" / "underfold-sshd-narrowing"
    / "run" / "run-underfold-001" / "gather_raw" / "l-001" / "0.json"
)

EXIT_OK = 0
EXIT_QUERY_ERROR = 1
EXIT_INPUT_ERROR = 2


def _sql(payload: str, query: str) -> subprocess.CompletedProcess:
    """Run the real tool over `payload` on stdin — no shim, no monkeypatch, no import.

    This is `cat <payload.json> | defender-sql '<query>'` as a lead types it: the module is
    a standalone program (no console-script entry point in `pyproject.toml`, and nothing
    named `defender-sql` on PATH in the test env), so the honest spelling is the
    interpreter plus the script path, which is how the shim is reached everywhere else.
    """
    return subprocess.run(
        [sys.executable, str(_SQL_PY), query],
        input=payload, capture_output=True, text=True, timeout=60,
    )


def _rows(payload: str, query: str) -> list:
    proc = _sql(payload, query)
    assert proc.returncode == EXIT_OK, f"defender-sql failed: {proc.stderr}"
    return json.loads(proc.stdout)


_HITS = json.dumps({
    "index": "logs-*", "total": 9189, "returned": 3, "truncated": True,
    "hits": [
        {"user": "alice", "host": "web-1"},
        {"user": "bob", "host": "web-1"},
        {"user": "alice", "host": "db-1"},
    ],
})

_TS_HITS = ('{"index":"logs-*","total":142,"returned":2,"truncated":true,"hits":['
            '{"@timestamp":"2026-08-07T11:32:52Z","user":"alice","message":"Failed password"},'
            '{"@timestamp":"2026-08-07T11:33:10Z","user":"bob","message":"Failed password"}]}')

#: The exact form `sql.py`'s search-hits hint hands back, minus its `WHERE` placeholder.
_SKELETON = 'SELECT h."@timestamp", h.message FROM (SELECT unnest(hits) h FROM data)'


# ---------------------------------------------------------------- O1: every shape queries


def test_hits_envelope_unnest_hits():
    """The modal shape. `unnest(hits)` binds a STRUCT only in the subquery form, and the
    worked answer is a count with a WHERE on a hit field — asserted on the VALUE, because
    "it did not crash" is what a wrong-shaped query does too when the filter matches nothing."""
    assert _rows(
        _HITS,
        "SELECT count(*) AS n FROM (SELECT unnest(hits) h FROM data) WHERE h.user = 'alice'",
    ) == [{"n": 2}]
    assert _rows(_HITS, "SELECT h.host AS host FROM (SELECT unnest(hits) h FROM data)") == [
        {"host": "web-1"}, {"host": "web-1"}, {"host": "db-1"},
    ]


def test_hits_envelope_truncation_columns_are_readable():
    """The envelope's own columns are queryable alongside its rows — which is what makes the
    `truncated` rule in `defender-sql.md` applicable at all. The zero-count is the paired
    control: a miss over a truncated payload is a real miss in the returned rows, and only
    the note (below) says it is not an absence."""
    assert _rows(_HITS, "SELECT total, returned, truncated FROM data") == [
        {"total": 9189, "returned": 3, "truncated": True},
    ]
    assert _rows(
        _HITS,
        "SELECT count(*) AS n FROM (SELECT unnest(hits) h FROM data) WHERE h.user = 'mallory'",
    ) == [{"n": 0}]


def test_esql_shape_on_the_real_tracked_payload():
    """`{columns, values, row_count}` — driven off the checked-in payload a lead was really
    handed, not a hand-written imitation. Bound to the adapter by
    `test_the_adapter_emits_the_shape_this_fixture_has`, which is what makes "a change to the
    ES|QL adapter's output shape breaks this" true rather than hopeful."""
    payload = _REAL_ESQL.read_text()
    doc = json.loads(payload)
    assert set(doc) >= {"columns", "row_count", "values"}, "the real fixture changed shape"
    assert _rows(payload, "SELECT row_count FROM data") == [{"row_count": 3}]
    assert _rows(payload, "SELECT count(*) AS n FROM (SELECT unnest(values) v FROM data)") \
        == [{"n": 3}]


def test_esql_values_are_positional_json_not_a_struct():
    """The trap: `unnest(values)` yields a POSITIONAL `JSON[]`, not the named struct
    `unnest(hits)` yields, so `v.<field>` — the idiom that is right one shape over — is a
    Binder Error here. The positional spelling is the paired positive control, and the
    `::BIGINT` cast is why the doc insists on it: `->>'$'` is TEXT, so `'412' < '9'` is true
    lexically and false numerically."""
    payload = _REAL_ESQL.read_text()

    struct_idiom = _sql(
        payload,
        'SELECT count(*) FROM (SELECT unnest(values) v FROM data) WHERE v."source.ip" = \'x\'',
    )
    assert struct_idiom.returncode == EXIT_QUERY_ERROR
    assert "not a struct" in struct_idiom.stderr

    assert _rows(
        payload,
        "SELECT count(*) AS n FROM (SELECT unnest(values) v FROM data) "
        "WHERE v[2]->>'$' = '203.0.113.7'",
    ) == [{"n": 1}]
    assert _rows(
        payload,
        "SELECT sum((v[1]->>'$')::BIGINT) AS failed FROM (SELECT unnest(values) v FROM data)",
    ) == [{"failed": 424}]
    lexical = "SELECT count(*) AS n FROM (SELECT unnest(values) v FROM data) WHERE {} < {}"
    assert _rows(payload, lexical.format("v[1]->>'$'", "'9'")) == [{"n": 2}]
    assert _rows(payload, lexical.format("(v[1]->>'$')::BIGINT", "9")) == [{"n": 1}]


def test_flat_object_is_one_row():
    """A cmdb/identity lookup is a flat object: one row, columns = its keys, no `unnest`."""
    payload = json.dumps({"host": "web-1", "owner": "team.platform", "criticality": "high"})
    assert _rows(payload, "SELECT owner FROM data") == [{"owner": "team.platform"}]
    assert _rows(payload, "SELECT * FROM data") == [
        {"host": "web-1", "owner": "team.platform", "criticality": "high"},
    ]


def test_bare_array_is_one_row_per_element():
    """A bare array of documents: one row per element, again no `unnest`."""
    payload = json.dumps([{"user": "alice"}, {"user": "bob"}, {"user": "alice"}])
    assert _rows(payload, "SELECT count(*) AS n FROM data WHERE user = 'alice'") == [{"n": 2}]
    assert _rows(payload, "SELECT count(*) AS n FROM data") == [{"n": 3}]


@pytest.mark.parametrize("shape", ["esql", "flat", "bare_array"])
def test_truncation_probe_is_shape_specific_not_universal(shape):
    """`SELECT total, returned, truncated FROM data` is a Binder Error on every shape but
    search-hits, so it cannot be taught as an unconditional first step. `DESCRIBE data` is
    the probe that runs on all of them — the paired positive control here, without which
    this test would only prove that a query can fail."""
    payload = {
        "esql": lambda: _REAL_ESQL.read_text(),
        "flat": lambda: json.dumps({"host": "web-1", "owner": "team.platform"}),
        "bare_array": lambda: json.dumps([{"user": "alice"}]),
    }[shape]()
    proc = _sql(payload, "SELECT total, returned, truncated FROM data")
    assert proc.returncode == EXIT_QUERY_ERROR
    assert "Binder Error" in proc.stderr
    assert _rows(payload, "DESCRIBE data")


# ------------------------------------------- O2: a wrong-shape query is told the real shape


def test_query_error_on_esql_shape_hint_gives_the_positional_map():
    """Struct access on ES|QL `values` fails, and the hint names the EXACT position of each
    field FOR THIS payload — grounded in the fixture's own `columns`, not a generic table.

    The runnable form is taken OUT of the hint text and executed, so the hint cannot hand
    back a recipe that does not run: `<value>` is the only thing substituted."""
    payload = _REAL_ESQL.read_text()
    doc = json.loads(payload)
    proc = _sql(
        payload,
        'SELECT count(*) FROM (SELECT unnest(values) v FROM data) WHERE v."source.ip" = \'x\'',
    )
    assert proc.returncode == EXIT_QUERY_ERROR
    assert "POSITIONAL JSON array" in proc.stderr
    assert "Positions: 1=failed, 2=source.ip" in proc.stderr
    for i, col in enumerate(doc["columns"]):
        assert f"{i + 1}={col['name']}" in proc.stderr

    form = "v[2]->>'$' = '<value>'"
    assert form in proc.stderr
    runnable = form.replace("<value>", doc["values"][0][1])
    assert _rows(
        payload,
        f"SELECT count(*) AS n FROM (SELECT unnest(values) v FROM data) WHERE {runnable}",
    ) == [{"n": 1}]


def test_the_esql_positional_map_is_derived_from_each_payloads_own_columns():
    """The test above reads ONE payload, so a hint holding a memorized `1=failed, 2=source.ip`
    would satisfy it while being a lie about every other ES|QL payload a lead is handed. This
    is a different payload — three columns, none of them the fixture's — and the map has to
    follow it, with the fixture's own positions nowhere in sight."""
    payload = json.dumps({
        "columns": [{"name": "host.name", "type": "keyword"},
                    {"name": "bytes", "type": "long"},
                    {"name": "user", "type": "keyword"}],
        "values": [["web-1", 4096, "alice"], ["db-1", 512, "bob"]],
        "row_count": 2,
    })
    proc = _sql(
        payload,
        'SELECT count(*) FROM (SELECT unnest(values) v FROM data) WHERE v."host.name" = \'x\'',
    )
    assert proc.returncode == EXIT_QUERY_ERROR
    assert "POSITIONAL JSON array" in proc.stderr
    assert "Positions: 1=host.name, 2=bytes, 3=user" in proc.stderr, (
        "the positional map did not follow this payload's own `columns`"
    )
    assert "failed" not in proc.stderr and "source.ip" not in proc.stderr, (
        "the hint carried the tracked fixture's columns into an unrelated payload — it is a "
        "memorized constant, not a map of the payload in hand"
    )

    # And the map is TRUE of this payload: position 2 is `bytes`, so the hint's own filter
    # form at position 2 selects on the byte count and nothing else.
    assert _rows(
        payload,
        "SELECT count(*) AS n FROM (SELECT unnest(values) v FROM data) "
        "WHERE v[2]->>'$' = '4096'",
    ) == [{"n": 1}]
    assert _rows(
        payload,
        "SELECT v[3]->>'$' AS who FROM (SELECT unnest(values) v FROM data) "
        "WHERE v[1]->>'$' = 'db-1'",
    ) == [{"who": "bob"}]


def test_query_error_on_hits_shape_hint_points_at_the_struct():
    """A wrong field name on the search-hits shape: the hint names the real top-level
    columns, hands back the subquery skeleton, and points at `DESCRIBE data` — which names
    the struct's fields AND their types in one call, where a sample row shows names only."""
    proc = _sql(_TS_HITS, "SELECT h.usr FROM (SELECT unnest(hits) h FROM data)")
    assert proc.returncode == EXIT_QUERY_ERROR
    assert "hint:" in proc.stderr
    assert "columns [index, total, returned, truncated, hits]" in proc.stderr
    assert "FROM (SELECT unnest(hits) h FROM data)" in proc.stderr
    assert "DESCRIBE data" in proc.stderr


def test_the_hits_hint_column_list_is_derived_from_each_payloads_own_keys():
    """The hits hint is checked above against ONE envelope, whose keys are the canonical
    `index, total, returned, truncated, hits` — so a hint that hardcoded that list would pass.

    This envelope carries `hits` under a different set of siblings (no `index`, no `total`, no
    `truncated`, plus keys the canonical one never has). The column list is the part of the
    hint that must be read off the payload in hand, and it has to name THESE keys, in the
    payload's own order, with none of the canonical ones invented alongside them. The `hits`
    branch is still the branch that is taken — the copyable form is the same — which is what
    separates "derived the columns" from "took a different branch"."""
    payload = json.dumps({
        "query": "user:alice", "hits": [{"user": "alice", "src": "10.0.0.1"}],
        "returned": 1, "note": "partial",
    })
    proc = _sql(payload, "SELECT h.nope FROM (SELECT unnest(hits) h FROM data)")
    assert proc.returncode == EXIT_QUERY_ERROR
    assert "columns [query, hits, returned, note]" in proc.stderr, (
        "the hint's column list did not follow this payload's own top-level keys"
    )
    assert "columns [index, total, returned, truncated, hits]" not in proc.stderr, (
        "the hint printed the canonical envelope's columns for a payload that has none of them"
    )
    assert "index" not in proc.stderr and "truncated" not in proc.stderr
    # Same branch, same copyable form — so the difference above is the derivation, not a
    # different shape being detected.
    assert _SKELETON in proc.stderr
    assert "DESCRIBE data" in proc.stderr


@pytest.mark.parametrize("query", [
    # the lateral-join spelling — duckdb answers `Candidate bindings: : "unnest"` and no more
    'SELECT h."@timestamp", h.message FROM data, unnest(hits) AS h',
    # the unquoted @-field — a parser error naming the character, not the fix
    "SELECT h.@timestamp FROM (SELECT unnest(hits) h FROM data)",
    # a wrong field on the struct
    "SELECT h.usr FROM (SELECT unnest(hits) h FROM data)",
    # and an error with nothing to do with the shape at all
    "SELEC * FROM data",
])
def test_hits_hint_hands_back_a_runnable_query_not_a_description(query):
    """A hint that describes the struct without showing the FROM form that binds it leaves a
    lead to guess the same wrong spelling again. Every error class therefore carries the
    copyable skeleton — and the skeleton is then executed here, so it cannot rot into a form
    that no longer runs."""
    proc = _sql(_TS_HITS, query)
    assert proc.returncode == EXIT_QUERY_ERROR
    assert _SKELETON in proc.stderr
    assert 'h."@timestamp"' in proc.stderr
    assert _rows('{"hits":[{"@timestamp":"t","message":"m"}]}', _SKELETON) \
        == [{"@timestamp": "t", "message": "m"}]


def test_the_hits_hint_form_runs_with_its_placeholders_filled():
    """The whole hint line, not just its FROM clause: the copy form ends in
    `WHERE h.<field> = '<value>'`, and filling only those two placeholders must yield a
    query that runs and answers correctly against the payload that produced the hint."""
    proc = _sql(_TS_HITS, "SELECT h.usr FROM (SELECT unnest(hits) h FROM data)")
    form = ('SELECT h."@timestamp", h.message FROM (SELECT unnest(hits) h FROM data) '
            "WHERE h.<field> = '<value>'")
    assert form in proc.stderr
    runnable = form.replace("h.<field>", "h.user").replace("<value>", "alice")
    assert _rows(_TS_HITS, runnable) == [
        {"@timestamp": "2026-08-07 11:32:52", "message": "Failed password"},
    ]


def test_each_error_class_gets_only_the_clause_that_answers_it():
    """duckdb self-answers most of what lands here (`Candidate Entries: "user"`, `Did you
    mean`), and a paragraph appended to every failure buries the one sentence that applies.
    So the shape skeleton is unconditional — it is what stops the NEXT query failing — while
    the prose clause is keyed to what duckdb actually said. An unrelated error gets the
    skeleton and nothing else: no lateral-join lecture, no quoting rule, no DESCRIBE."""
    lateral = _sql(_TS_HITS, 'SELECT h."@timestamp" FROM data, unnest(hits) AS h').stderr
    assert "binds `h` to the TABLE" in lateral
    assert "column is called `unnest`" in lateral

    at_field = _sql(_TS_HITS, "SELECT h.@timestamp FROM (SELECT unnest(hits) h FROM data)").stderr
    assert "must be double-quoted" in at_field, "the @-quoting error did not get the quoting rule"
    assert "TABLE" not in at_field, "a parser error about `@` was handed the lateral-join lecture"

    struct_key = _sql(_TS_HITS, "SELECT h.usr FROM (SELECT unnest(hits) h FROM data)").stderr
    assert "DESCRIBE data" in struct_key
    assert "TABLE" not in struct_key
    assert "double-quoted" not in struct_key

    for unrelated in ("SELEC * FROM data", "SELECT * FROM dat"):
        stderr = _sql(_TS_HITS, unrelated).stderr
        assert _SKELETON in stderr, "an unrelated error lost the copyable skeleton"
        assert "TABLE" not in stderr, f"{unrelated!r} was handed the lateral-join lecture"
        assert "double-quoted" not in stderr
        assert "DESCRIBE data" not in stderr


def test_the_clause_is_keyed_off_duckdbs_message_not_off_the_querys_own_text():
    """The four probes above are separable by their own SQL text just as cleanly as by what
    duckdb said, so a dispatch that pattern-matched the QUERY — `", unnest("` means lateral,
    `".@"` means quoting — would pass the whole of it and then go silent on the next lead who
    spelled the same mistake differently.

    So: the same two error CLASSES, respelled. A different lateral alias (`ev`, not `h`), and
    a different `@`-field under a different subquery alias (`rec.@version`, not `h.@timestamp`,
    on a field this payload does not even carry). Each must get the SAME clause as its sibling
    above — which only a dispatch reading duckdb's message can do, because the query text it
    would have keyed on is gone."""
    lateral = _sql(_TS_HITS, "SELECT ev.message FROM data, unnest(hits) AS ev").stderr
    assert "Candidate bindings" in lateral, "this probe stopped producing the lateral-join error"
    assert "binds `h` to the TABLE" in lateral, (
        "a lateral join under a different alias lost the lateral-join clause — the clause is "
        "keyed off the query's text, not off duckdb's message"
    )
    assert "column is called `unnest`" in lateral
    assert "double-quoted" not in lateral

    at_field = _sql(
        _TS_HITS, "SELECT rec.@version FROM (SELECT unnest(hits) rec FROM data)",
    ).stderr
    assert 'syntax error at or near "@"' in at_field, "this probe stopped being a parser error"
    assert "must be double-quoted" in at_field, (
        "an unquoted `@`-field under a different alias lost the quoting rule — the rule is "
        "keyed off the query's text, not off duckdb's message"
    )
    assert "TABLE" not in at_field
    assert "DESCRIBE data" not in at_field

    # The skeleton is unconditional, so both respellings still carry the form that binds.
    assert _SKELETON in lateral
    assert _SKELETON in at_field


def test_the_lateral_join_hint_states_what_duckdb_actually_does():
    """The hint's claim about the spelling it rules out has to be TRUE, or it teaches a
    second wrong fact while fixing the first. `FROM data, unnest(hits) AS h` does bind — `h`
    is the table alias and its one column is named `unnest`, which is exactly why
    `h.<field>` misses. Both halves are executed so the sentence cannot drift into folklore."""
    payload = '{"hits":[{"@timestamp":"t","message":"m"}]}'
    assert _rows(payload, 'SELECT h.unnest."@timestamp" AS ts FROM data, unnest(hits) AS h') \
        == [{"ts": "t"}]
    assert _rows(payload, 'SELECT u."@timestamp" AS ts FROM data, unnest(hits) AS t(u)') \
        == [{"ts": "t"}]


def test_query_error_on_flat_shape_hint_names_the_columns():
    """On a flat payload the hint's job is just the column list plus "no `unnest`" — and the
    `SELECT * FROM data` it offers is run here as the paired control."""
    payload = '{"host":"web-1","owner":"team.platform"}'
    proc = _sql(payload, "SELECT nope FROM data")
    assert proc.returncode == EXIT_QUERY_ERROR
    assert "columns [host, owner]" in proc.stderr
    assert "SELECT * FROM data" in proc.stderr
    assert "unnest(hits)" not in proc.stderr, "a flat payload was handed the search-hits idiom"
    assert _rows(payload, "SELECT * FROM data") == [{"host": "web-1", "owner": "team.platform"}]


# ------------------------------------------------------- O3: a result that would lie says so


def test_truncated_payload_warns_on_a_successful_query():
    """The truncation trap lives in the TOOL, not only in the prose: a successful query over
    a truncated payload carries a stderr note, because the tool can see `truncated` and the
    caller reading a `0` may not."""
    proc = _sql(
        '{"total":9,"returned":1,"truncated":true,"hits":[{"user":"a"}]}',
        "SELECT count(*) AS n FROM (SELECT unnest(hits) h FROM data) WHERE h.user = 'mallory'",
    )
    assert proc.returncode == EXIT_OK
    assert json.loads(proc.stdout) == [{"n": 0}]
    assert "TRUNCATED" in proc.stderr
    assert "cannot support an absence refutation" in proc.stderr


def test_non_truncated_payload_emits_no_note():
    """The note fires ONLY on `truncated` being set — the same query over the same shape with
    the flag down is silent, so the signal keeps meaning something."""
    proc = _sql(
        '{"total":2,"returned":2,"truncated":false,"hits":[{"user":"a"}]}',
        "SELECT count(*) AS n FROM (SELECT unnest(hits) h FROM data) WHERE h.user = 'mallory'",
    )
    assert proc.returncode == EXIT_OK
    assert json.loads(proc.stdout) == [{"n": 0}]
    assert proc.stderr.strip() == ""


def test_the_note_keys_on_truncated_not_on_returned_being_short_of_total():
    """The two payloads above have `truncated` and `returned < total` moving together, so a
    note keyed on the ARITHMETIC would pass both. These two pull the signals apart.

    `truncated` is the source's own statement that it stopped early; `returned < total` is an
    inference that is wrong in both directions. A page-sized source can set `truncated` on a
    page that happens to be the whole match set (dedup, a post-filter, a `total` that is an
    estimate) — the caller still must not read a miss as an absence. And `total` is routinely
    a match count from a different scope than `hits` (a count over the index vs. the rows this
    query returned), so `returned < total` on an untruncated payload is normal and a note there
    would cry wolf on every well-formed result.
    """
    flagged_but_complete = _sql(
        '{"total":1,"returned":1,"truncated":true,"hits":[{"user":"a"}]}',
        "SELECT count(*) AS n FROM (SELECT unnest(hits) h FROM data) WHERE h.user = 'mallory'",
    )
    assert flagged_but_complete.returncode == EXIT_OK
    assert json.loads(flagged_but_complete.stdout) == [{"n": 0}]
    assert "TRUNCATED" in flagged_but_complete.stderr, (
        "`truncated: true` with `returned == total` lost the note — the note is keyed on "
        "`returned < total` rather than on the flag the source actually set"
    )
    assert "cannot support an absence refutation" in flagged_but_complete.stderr

    short_but_complete = _sql(
        '{"total":900,"returned":1,"truncated":false,"hits":[{"user":"a"}]}',
        "SELECT count(*) AS n FROM (SELECT unnest(hits) h FROM data) WHERE h.user = 'mallory'",
    )
    assert short_but_complete.returncode == EXIT_OK
    assert json.loads(short_but_complete.stdout) == [{"n": 0}]
    assert short_but_complete.stderr.strip() == "", (
        "`truncated: false` with `returned < total` fired the note — the note is keyed on the "
        "arithmetic, so it will fire on every payload whose `total` is a wider-scope count"
    )


def test_empty_payload_is_an_error_not_an_empty_result():
    """An empty payload file is common, and `jq` exited 0 printing nothing on one — which
    reads downstream as "the entity is absent". This exits 2 and says so, and prints NO rows
    on stdout, so an empty result set can never be confused with a missing observation."""
    proc = _sql("   ", "SELECT count(*) FROM data")
    assert proc.returncode == EXIT_INPUT_ERROR
    assert proc.stdout == ""
    assert "no input on stdin" in proc.stderr
    assert "NOT an empty result set" in proc.stderr


def test_markdown_payload_is_an_input_error():
    """The other non-payload: an adapter's rendered text rather than JSON. Same contract —
    exit 2, nothing on stdout, a message that names the cause."""
    proc = _sql("## Query Results\n\n- **Matching events:** 197\n", "SELECT count(*) FROM data")
    assert proc.returncode == EXIT_INPUT_ERROR
    assert proc.stdout == ""
    assert "not valid JSON" in proc.stderr


def test_a_real_payload_on_the_same_query_is_not_an_input_error():
    """The control for the two above: the identical query over a well-formed payload exits 0
    with rows, so "exit 2" is a judgement about the input and not about the query."""
    assert _rows('{"hits":[{"user":"a"}]}', "SELECT count(*) AS n FROM data") == [{"n": 1}]


# ---------------------------------------------- O4: the fixture is bound to the real adapter


def test_the_adapter_emits_the_shape_this_fixture_has():
    """The guard that stops the ES|QL tests above from testing a file instead of the code.

    A checked-in fixture asserts nothing about production: the adapter once learned to re-zip
    `values` into per-row dicts while the fixture went on saying positional, and every
    assertion against the file kept passing against a shape production had stopped emitting —
    which is how `sql.py`'s ES|QL hint and `defender-sql.md` came to teach a recipe that
    raises a Binder Error. So bind to the ADAPTER. `esql_payload` is the pure shaping step —
    no HTTP, no transport seam, nothing to monkeypatch — and re-introducing the zip inside it
    turns this red.

    The wire response is rebuilt FROM THE FIXTURE's own `columns` and `values`, so the
    adapter is driven at the fixture's real size — three rows — rather than at a hand-written
    two. A re-zip that only trips above a row count (a `len(values) > 2` fast path, a
    batch-size branch) is invisible to a two-row probe, and two rows is also the one width at
    which a transposed zip is hard to tell from an untransposed one. Feeding the fixture's own
    input makes the binding bidirectional: the fixture is what the adapter is asked to
    produce, and the adapter is what the fixture is checked against.
    """
    fixture = json.loads(_REAL_ESQL.read_text())
    assert len(fixture["values"]) == 3, "the fixture shrank — this test is no longer at its size"
    raw = {"columns": fixture["columns"], "values": fixture["values"]}
    payload = esql_payload("FROM logs-* | STATS failed = COUNT(*) BY source.ip", raw)

    assert payload["values"] == raw["values"], "the adapter re-shaped rows the wire had sent"
    assert all(isinstance(row, list) for row in payload["values"]), (
        "rows arrived as dicts — the re-zip is back, and `defender-sql.md` plus sql.py's "
        "ES|QL hint now teach an idiom that cannot run"
    )
    assert payload["columns"] == raw["columns"]
    assert payload["row_count"] == len(raw["values"]) == 3

    # Positionally, cell by cell, against the file the ES|QL tests above read: not just "still
    # a list of lists" but the SAME rows in the SAME order with cell `i` under `columns[i]`.
    # A transpose, a row reversal or a partial re-zip all survive a shape-only check.
    assert payload["values"] == [[412, "203.0.113.7"], [9, "198.51.100.22"], [3, "203.0.113.40"]]
    for emitted, expected in zip(payload["values"], fixture["values"], strict=True):
        assert emitted == expected, "the adapter's rows diverged from the tracked fixture's"
        assert len(emitted) == len(payload["columns"]), (
            "a row is not one cell per column — the positional binding `defender-sql.md` "
            "teaches cannot be derived from `columns`"
        )
    assert [c["name"] for c in payload["columns"]] == ["failed", "source.ip"]

    # The fixture predates the envelope's `query` key, so it is a SUBSET of what the adapter
    # emits, not an equal — the tests above read `columns`/`values`/`row_count` and nothing
    # else. What has to match is the row shape, which is the thing that drifted.
    assert set(fixture) <= set(payload), \
        f"fixture carries keys the adapter does not: {set(fixture) - set(payload)}"
    assert isinstance(fixture["values"][0], list), "the fixture drifted off the adapter's shape"
    assert fixture["row_count"] == len(fixture["values"]) == payload["row_count"]


# ------------------------------------------------ O5: no lead-facing surface teaches the dead


#: Everything a gather lead reads or runs when it writes SQL over a payload.
_LEAD_SURFACES = (
    DEFENDER / "scripts" / "gather_tools" / "sql.py",
    DEFENDER / "skills" / "connect" / "adapter.md",
    _DOC,
)


#: Every spelling of reaching THROUGH a `result` wrapper to `hits`: the dotted form, the
#: bracket-subscript form a doc reaches for when the key has a dot in it, and either with the
#: whitespace a reflowed sentence or a formatter leaves behind. A literal `"result.hits"`
#: census is defeated by `result['hits']`, which teaches the identical dead recipe.
_DEAD_ENVELOPE = re.compile(r"result\s*[.\[]\s*['\"]?hits")


@pytest.mark.parametrize("surface", _LEAD_SURFACES, ids=lambda p: p.name)
def test_no_lead_facing_surface_resurrects_the_result_envelope(surface):
    """`unnest(result.hits)` has no home anywhere: no adapter emits a `result` wrapper, so
    the recipe belonged to a code path that is gone. It is currently absent from all three
    surfaces and this is the ratchet that keeps it absent — `sql.py`'s argparse epilog went
    on teaching it long after the module docstring stopped, and `defender-sql --help` is
    inside the lead's bash lane, one `--help` away from being copied back into a query."""
    text = surface.read_text()
    assert "result.hits" not in text, f"{surface.name} re-teaches the dead recipe"
    found = _DEAD_ENVELOPE.search(text)
    assert found is None, (
        f"{surface.name} re-teaches the dead recipe under another spelling: {found.group(0)!r}"
    )
    # Paired control: the census is over a file that really does discuss the hits shape, so a
    # zero here cannot come from reading the wrong (or an empty) file.
    assert "hits" in text, f"{surface.name} no longer mentions the hits shape at all"


def test_the_help_epilog_the_lead_actually_prints_is_clean_too():
    """The census above reads `sql.py` as a FILE. What a lead reads is `--help`, and argparse
    reflows the epilog to the terminal width — a recipe that survives the source census can
    still be broken across a line, and a recipe reintroduced through argparse's `%(prog)s`
    interpolation is not in the source text at all. So run the program and read its output.

    The paired control is the live idiom: the epilog is asserted to be a surface that really
    does hand the lead a hits query, so a clean census here cannot come from an epilog that
    says nothing."""
    proc = subprocess.run(
        [sys.executable, str(_SQL_PY), "--help"],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == EXIT_OK
    # Unwrapped as well as raw: argparse breaks the epilog at the terminal width, so a recipe
    # can be present in what the lead reads while no single line of it contains the spelling.
    unwrapped = " ".join((proc.stdout + proc.stderr).split())
    for printed in ((proc.stdout + proc.stderr), unwrapped):
        assert "result.hits" not in printed, "`--help` re-teaches the dead recipe"
        found = _DEAD_ENVELOPE.search(printed)
        assert found is None, (
            f"`--help` re-teaches the dead recipe under another spelling: {found.group(0)!r}"
        )
    # The control: this really is the surface that teaches the hits binding.
    assert "unnest(hits) h FROM data" in unwrapped
    assert "no wrapper envelope to reach" in unwrapped


def test_the_dead_recipe_stays_dead():
    """Why the census above is worth having: the recipe does not merely look stale, it FAILS.
    Pinning the failure keeps anyone from reintroducing it on the strength of an old doc."""
    proc = _sql(_HITS, "SELECT count(*) FROM (SELECT unnest(result.hits) h FROM data)")
    assert proc.returncode == EXIT_QUERY_ERROR
    assert "Binder Error" in proc.stderr
    assert 'Referenced table "result" not found' in proc.stderr
    # and the live spelling, on the same payload, works
    assert _rows(_HITS, "SELECT count(*) AS n FROM (SELECT unnest(hits) h FROM data)") \
        == [{"n": 3}]


# ------------------------------------ doc binding: what defender-sql.md prints, run verbatim


#: A struct-style field access on an ES|QL `values` row — `v.host`, `v."source.ip"`. The
#: placeholder `v.<field>` the doc uses to NAME the failing idiom is deliberately not matched:
#: what is banned is a concrete field spelled after `v.`, which is a recipe rather than a
#: citation. `(?<![A-Za-z0-9_])` keeps a hostname or a version string from counting.
_STRUCT_ACCESS_ON_V = re.compile(r"(?<![A-Za-z0-9_])v\s*\.\s*[A-Za-z_\"]")

#: Phrasings that would retract the cast rule while leaving its example in place.
_CAST_RETRACTIONS = (
    "no cast", "without a cast", "already typed", "already a number", "already numeric",
    "cast is not", "casting is not", "no need to cast", "need not be cast", "returns a number",
)


def _sql_fences(text: str) -> list[str]:
    """The doc's ```sql blocks — what a lead copies, as opposed to what the prose discusses."""
    return re.findall(r"```sql\n(.*?)```", text, re.S)


def test_the_docs_esql_example_is_literal_and_runs():
    """`defender-sql.md`'s ES|QL example, asserted present as a LITERAL and then executed —
    the same string, unedited — against the real fixture. Bound to the string rather than
    parsed out of the fence, so an edit to the doc's recipe must come here and be re-run
    rather than quietly redefining what is tested."""
    example = "SELECT v[2]->>'$' FROM (SELECT unnest(values) v FROM data)"
    doc = _DOC.read_text()
    assert example in doc, "the doc's ES|QL example changed"

    # Present is not enough: a doc that ALSO teaches the struct spelling teaches a Binder
    # Error, and a lead who reaches the wrong recipe first has still lost the turn. `values`
    # rows are positional arrays, so no concrete field may ever be spelled after `v.`.
    struct_access = _STRUCT_ACCESS_ON_V.search(doc)
    assert struct_access is None, (
        f"the doc teaches struct access on an ES|QL row ({struct_access.group(0)!r}) — "
        "`unnest(values)` yields a POSITIONAL array and this raises a Binder Error"
    )
    # And the placeholder form it DOES name is named as a failure, not offered as a recipe:
    # every `v.<field>` in the doc sits next to the word that rules it out.
    assert "v.<field>" in doc
    assert re.search(r"`v\.<field>`\s*fails", doc), (
        "the doc mentions `v.<field>` without saying it fails"
    )
    # The copyable fences are the positional form only — no fence hands back struct access.
    fences = _sql_fences(doc)
    assert example.strip() in [f.strip() for f in fences], "the ES|QL example left the fences"
    for fence in fences:
        assert _STRUCT_ACCESS_ON_V.search(fence) is None, f"a copyable fence cannot run: {fence!r}"

    payload = _REAL_ESQL.read_text()
    rows = _rows(payload, example)
    # One unaliased column per row, so the KEY is duckdb's generated name for the expression
    # (`(v[2] ->> '$')` today) and is not part of this contract across a `duckdb>=1.5,<2`
    # bump. The values are: position 2 is `source.ip`, in the fixture's own row order.
    assert [list(row.values()) for row in rows] == [
        ["203.0.113.7"], ["198.51.100.22"], ["203.0.113.40"],
    ]


def test_the_docs_bigint_cast_rule_is_literal_and_runs():
    """The doc's cast rule, the same way: the literal `(v[3]->>'$')::BIGINT` must be in the
    file and must PARSE AND RUN as written (position 3 is past this fixture's two columns, so
    it yields NULL rather than an error — the cast itself is what is under test). The same
    cast at a position the fixture has gives the real number, and the uncast comparison gives
    the wrong one, which is the claim the rule exists to make."""
    rule = "(v[3]->>'$')::BIGINT"
    doc = _DOC.read_text()
    assert rule in doc, "the doc's ::BIGINT cast rule changed"
    assert "returns **TEXT**" in doc

    # A rule stated and then retracted a sentence later is worse than no rule: the lead reads
    # the retraction as the exception that applies to it. Nothing in the doc may say the cast
    # is optional, and nothing may claim `->>'$'` hands back anything but TEXT.
    low = doc.lower()
    for retraction in _CAST_RETRACTIONS:
        assert retraction not in low, (
            f"the doc retracts its own cast rule with {retraction!r}"
        )
    for wrong_type in ("returns **BIGINT", "returns **INTEGER", "returns **JSON", "returns a BIGINT"):
        assert wrong_type.lower() not in low, f"the doc misstates `->>'$'`'s type: {wrong_type!r}"
    # And the consequence is still stated, so the rule is a reason rather than an incantation.
    assert "lexical" in low, "the doc dropped WHY the cast is required"

    payload = _REAL_ESQL.read_text()
    unnested = "FROM (SELECT unnest(values) v FROM data)"
    assert _rows(payload, f"SELECT {rule} AS n {unnested}") == [{"n": None}] * 3

    at_real_position = rule.replace("v[3]", "v[1]")
    assert _rows(payload, f"SELECT {at_real_position} AS failed {unnested}") == [
        {"failed": 412}, {"failed": 9}, {"failed": 3},
    ]
    assert _rows(payload, f"SELECT count(*) AS n {unnested} WHERE {at_real_position} < 9") \
        == [{"n": 1}]
    assert _rows(payload, f"SELECT count(*) AS n {unnested} WHERE v[1]->>'$' < '9'") \
        == [{"n": 2}], "the uncast comparison is supposed to be lexical — that is the point"


def test_the_docs_hits_idiom_is_literal_and_runs():
    """The doc's search-hits binding, same treatment: present as a literal, then executed
    with only its `<field>`/`<other>`/`<value>` placeholders filled."""
    idiom = ("SELECT h.<field> FROM (SELECT unnest(hits) h FROM data) "
             "WHERE h.<other> = '<value>'")
    doc = _DOC.read_text()
    assert idiom in doc, "the doc's search-hits idiom changed"

    # The lateral form is the one that looks right and binds `h` to the TABLE. It may appear
    # ONLY as the named trap, never as something a lead copies: no fence carries it, and every
    # occurrence sits inside the sentence that rules it out.
    for fence in _sql_fences(doc):
        assert "unnest(hits) AS" not in fence and ", unnest(hits)" not in fence, (
            f"a copyable fence hands back the lateral form, which does not bind: {fence!r}"
        )
    assert idiom.strip() in [f.strip() for f in _sql_fences(doc)], (
        "the subquery form left the copyable fences"
    )
    occurrences = [m.start() for m in re.finditer(r"FROM data,\s*unnest\(hits\)", doc)]
    for start in occurrences:
        window = doc[max(0, start - 250):start + 350]
        assert any(marker in window for marker in (
            "does not do what it looks like", "names the TABLE", "does not resolve",
        )), "the lateral form appears without the caveat that it does not bind"
    # The AS-less lateral spelling has never been in this doc; keep it that way.
    assert "FROM data, unnest(hits) h" not in doc, "the doc now teaches a lateral form that misbinds"

    runnable = (idiom.replace("h.<field>", "h.user AS user")
                     .replace("h.<other>", "h.host")
                     .replace("<value>", "web-1"))
    assert _rows(_HITS, runnable) == [{"user": "alice"}, {"user": "bob"}]
