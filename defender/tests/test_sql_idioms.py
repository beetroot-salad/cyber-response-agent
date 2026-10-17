"""The SQL idioms a gather lead is taught run through the real `defender-sql` subprocess: one binding per payload shape (search hits, ES|QL declared rows, flat object, bare array), the hints on a query error, truncation notes, and the arrow-precedence refusals. Internals (sandbox, column disambiguation) are in test_sql.py."""
from __future__ import annotations

import json
import re
import subprocess

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
from defender.tests._locale import C_LOCALE_ENV


#: The real ES|QL payload a lead was handed in a checked-in scenario run: `columns`
#: `failed:long, source.ip:ip`, three POSITIONAL rows, `row_count: 3`. Hand-writing this
#: shape is what let it drift once already (see `test_the_adapter_emits_the_shape_this_fixture_has`).
_REAL_ESQL = (
    DEFENDER / "evals" / "scenarios_lead" / "underfold-sshd-narrowing"
    / "run" / "run-underfold-001" / "gather_raw" / "l-001" / "0.json"
)

@pytest.fixture(scope="module")
def esql() -> str:
    """The real ES|QL payload, as text — what goes on the tool's stdin."""
    return read_text_utf8(_REAL_ESQL)


def _sql(
    payload: str, query: str, env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """`cat <payload.json> | defender-sql '<query>'` as a lead types it."""
    return run_sql_warm(query, stdin=payload, env=env)


def _rows(payload: str, query: str) -> list:
    proc = _sql(payload, query)
    assert proc.returncode == EXIT_OK, f"defender-sql failed: {proc.stderr}"
    return json.loads(proc.stdout)


#: The declaration an ES|QL payload is queried under (#1138): rows at `values`, names at `columns`.
_ESQL_DECLARED = ("--rows", "values", "--names", "columns")


def _declared(payload: str, query: str, declaration: tuple[str, ...] = _ESQL_DECLARED) -> list:
    """`cat <payload.json> | defender-sql --rows … --names … '<query>'` — the declared form."""
    proc = run_sql_warm(*declaration, query, stdin=payload)
    assert proc.returncode == EXIT_OK, f"defender-sql failed: {proc.stderr}"
    return json.loads(proc.stdout)


def _hint(proc: subprocess.CompletedProcess) -> str:
    """What the TOOL added to a query error, and nothing duckdb said."""
    _, marker, hint = proc.stderr.partition("hint:")
    assert marker, f"no hint on stderr: {proc.stderr!r}"
    return hint


def _fill(template: str, subs: dict[str, str]) -> str:
    """Substitute every `placeholder -> value` pair into `template`, in one place instead of
    a bespoke `.replace()` chain per call site — order follows `subs`'s own insertion order."""
    for placeholder, value in subs.items():
        template = template.replace(placeholder, value)
    return template


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


def test_esql_shape_on_the_real_tracked_payload(esql):
    """`{columns, values, row_count}` — driven off the checked-in payload a lead was really
    handed, not a hand-written imitation. Bound to the adapter by
    `test_the_adapter_emits_the_shape_this_fixture_has`, which is what makes "a change to the"""
    assert set(json.loads(esql)) >= {"columns", "row_count", "values"}, "the real fixture changed shape"
    assert _declared(esql, "SELECT count(*) AS n FROM data") == [{"n": 3}]
    assert [(r["column_name"], r["column_type"]) for r in _declared(esql, "DESCRIBE data")] == [
        ("failed", "BIGINT"), ("source.ip", "VARCHAR")]
    assert _rows(esql, "SELECT row_count FROM data") == [{"row_count": 3}]


def test_esql_rows_are_queried_by_name_once_declared(esql):
    """The trap the positional recipe lived in: `unnest(values)` yields a POSITIONAL `JSON[]`,
    so the struct spelling `v."source.ip"` is a Binder Error — still, unflagged — and the only
    way through was `v[N]->>'$'` plus a cast, because `->>'$'` is TEXT and `'412' < '9'` is true"""
    struct_idiom = _sql(
        esql,
        'SELECT count(*) FROM (SELECT unnest(values) v FROM data) WHERE v."source.ip" = \'x\'',
    )
    # A refusal is the contract; duckdb's own wording of WHY (`not a struct` today) is not.
    assert_query_error(struct_idiom, "the struct spelling was not refused")
    assert "--rows values --names columns" in struct_idiom.stderr, struct_idiom.stderr

    assert _declared(esql, 'SELECT count(*) AS n FROM data WHERE "source.ip" = \'203.0.113.7\'') \
        == [{"n": 1}]
    assert _declared(esql, "SELECT sum(failed) AS failed FROM data") == [{"failed": 424}]
    # Numeric, not lexical: only 3 is below 9 (as text, '412' is too).
    assert _declared(esql, "SELECT count(*) AS n FROM data WHERE failed < 9") == [{"n": 1}]


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
def test_truncation_probe_is_shape_specific_not_universal(shape, esql):
    """`SELECT total, returned, truncated FROM data` is a Binder Error on every shape but
    search-hits, so it cannot be taught as an unconditional first step. `DESCRIBE data` is
    the probe that runs on all of them — the paired positive control here, without which
    this test would only prove that a query can fail."""
    payload = {
        "esql": esql,
        "flat": json.dumps({"host": "web-1", "owner": "team.platform"}),
        "bare_array": json.dumps([{"user": "alice"}]),
    }[shape]
    proc = _sql(payload, "SELECT total, returned, truncated FROM data")
    assert_query_error(proc, "the envelope columns resolved on a payload that has none")
    assert _rows(payload, "DESCRIBE data")


# ------------------------------------------- O2: a wrong-shape query is told the real shape


#: The clause of a hint that is DERIVED from the payload in hand. "The other payload's names
#: are absent" is asserted of it, not of the idiom prose around it.
_COLUMNS_CLAUSE = re.compile(r"columns \[[^\]]*\]")
#: The declaration the unflagged note hands back (#1138 O6), as flag values.
_DECLARATION = re.compile(r"--rows (\S+) --names (\S+)")


def _clause(hint: str, pattern: re.Pattern[str]) -> str:
    found = pattern.search(hint)
    assert found, f"no {pattern.pattern!r} clause in the hint: {hint!r}"
    return found.group(0)


def _declaration(proc: subprocess.CompletedProcess) -> tuple[str, ...]:
    """The `--rows X --names Y` the tool printed, as argv — taken OUT of stderr so the test runs
    exactly what the lead would copy."""
    found = _DECLARATION.search(proc.stderr)
    assert found, f"no declaration on stderr: {proc.stderr!r}"
    return ("--rows", found.group(1), "--names", found.group(2))


def test_query_error_on_esql_shape_names_the_declaration_that_binds_it(esql):
    """Struct access on ES|QL `values` fails, and the tool's answer is no longer a positional
    map with a `->>'$'` form (#1138 O6/O9): it names the declaration that makes the rows a table,
    for THIS payload — and that declaration, taken out of stderr and run, answers."""
    payload_doc = json.loads(esql)
    proc = _sql(
        esql,
        'SELECT count(*) FROM (SELECT unnest(values) v FROM data) WHERE v."source.ip" = \'x\'',
    )
    assert proc.returncode == EXIT_QUERY_ERROR
    assert _declaration(proc) == _ESQL_DECLARED
    # The query holds no arrow, so any `->>` on stderr is the tool's own text. Read off the
    # whole of stderr rather than a `hint:` section: on a positional payload the tool names the
    # declaration, and need not print the shape hint at all (#1138 review, R1).
    assert "Positions:" not in proc.stderr
    assert "->>" not in proc.stderr, f"stderr still teaches the positional recipe: {proc.stderr!r}"
    assert "flat/array" not in proc.stderr, "a positional payload was handed the flat idiom"

    value = payload_doc["values"][0][1]
    assert _declared(esql, f'SELECT count(*) AS n FROM data WHERE "source.ip" = \'{value}\'',
                     _declaration(proc)) == [{"n": 1}]


def test_the_declaration_the_note_names_is_derived_from_each_payloads_own_keys():
    """The test above reads ONE payload, so a note holding a memorized `--rows values --names
    columns` would satisfy it while being a lie about every other positional payload a lead is
    handed. This is a Splunk-shaped one — `fields` and `rows`, three columns, none of them the
    fixture's — and the declaration has to follow it, with ES|QL's keys nowhere in it."""
    payload_doc = {
        "fields": ["host.name", "bytes", "user"],
        "rows": [["web-1", 4096, "alice"], ["db-1", 512, "bob"]],
        "count": 2,
    }
    payload = json.dumps(payload_doc)
    proc = _sql(payload, "SELECT nope FROM data")
    assert proc.returncode == EXIT_QUERY_ERROR
    declaration = _declaration(proc)
    assert declaration == ("--rows", "rows", "--names", "fields"), (
        "the declaration did not follow this payload's own keys"
    )

    # And the declaration is TRUE of this payload: run as printed, `bytes` is the number column.
    assert _declared(payload, "SELECT user FROM data WHERE bytes = 512", declaration) \
        == [{"user": "bob"}]
    assert _declared(payload, 'SELECT "host.name" FROM data WHERE bytes > 1000', declaration) \
        == [{"host.name": "web-1"}]


def test_query_error_on_hits_shape_hint_points_at_the_struct():
    """A wrong field name on the search-hits shape: the hint names the real top-level
    columns, hands back the subquery skeleton, and points at `DESCRIBE data` — which names
    the struct's fields AND their types in one call, where a sample row shows names only."""
    proc = _sql(_TS_HITS, "SELECT h.usr FROM (SELECT unnest(hits) h FROM data)")
    assert proc.returncode == EXIT_QUERY_ERROR
    hint = _hint(proc)
    assert "columns [index, total, returned, truncated, hits]" in hint
    assert "FROM (SELECT unnest(hits) h FROM data)" in hint
    assert "DESCRIBE data" in hint


def test_the_hits_hint_column_list_is_derived_from_each_payloads_own_keys():
    """The hits hint is checked above against ONE envelope, whose keys are the canonical
    `index, total, returned, truncated, hits` — so a hint that hardcoded that list would pass."""
    payload = json.dumps({
        "query": "user:alice", "hits": [{"user": "alice", "src": "10.0.0.1"}],
        "returned": 1, "note": "partial",
    })
    proc = _sql(payload, "SELECT h.nope FROM (SELECT unnest(hits) h FROM data)")
    assert proc.returncode == EXIT_QUERY_ERROR
    hint = _hint(proc)
    columns = _clause(hint, _COLUMNS_CLAUSE)
    assert columns == "columns [query, hits, returned, note]", (
        "the hint's column list did not follow this payload's own top-level keys"
    )
    for canonical_only in ("index", "total", "truncated"):
        assert canonical_only not in columns, (
            "the hint printed a canonical envelope column for a payload that does not have it"
        )
    # Same branch, same copyable form — so the difference above is the derivation, not a
    # different shape being detected.
    assert _SKELETON in hint
    assert "DESCRIBE data" in hint


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
    copyable skeleton, unconditionally — that the skeleton itself is runnable is pinned once,
    below, rather than re-spawned per parametrize case here."""
    proc = _sql(_TS_HITS, query)
    assert proc.returncode == EXIT_QUERY_ERROR
    assert _SKELETON in _hint(proc)


def test_the_skeleton_every_hint_hands_back_is_runnable_on_its_own():
    """The fixed control for the parametrized check above: the copyable skeleton is the same
    string regardless of which wrong query produced the hint, so it is executed once here
    rather than once per error class, and it cannot rot into a form that no longer runs."""
    assert _rows('{"hits":[{"@timestamp":"t","message":"m"}]}', _SKELETON) \
        == [{"@timestamp": "t", "message": "m"}]


def test_the_hits_hint_form_runs_with_its_placeholders_filled():
    """The whole hint line, not just its FROM clause: the copy form ends in
    `WHERE h.<field> = '<value>'`, and filling only those two placeholders must yield a
    query that runs and answers correctly against the payload that produced the hint."""
    proc = _sql(_TS_HITS, "SELECT h.usr FROM (SELECT unnest(hits) h FROM data)")
    form = ('SELECT h."@timestamp", h.message FROM (SELECT unnest(hits) h FROM data) '
            "WHERE h.<field> = '<value>'")
    assert form in _hint(proc)
    runnable = _fill(form, {"h.<field>": "h.user", "<value>": "alice"})
    # `message` only: how duckdb types and prints an ISO `Z` string is duckdb's, not the hint's.
    assert [row["message"] for row in _rows(_TS_HITS, runnable)] == ["Failed password"]


def test_each_error_class_gets_only_the_clause_that_answers_it():
    """duckdb self-answers most of what lands here (`Candidate Entries: "user"`, `Did you
    mean`), and a paragraph appended to every failure buries the one sentence that applies."""
    lateral = _hint(_sql(_TS_HITS, 'SELECT h."@timestamp" FROM data, unnest(hits) AS h'))
    assert "binds `h` to the TABLE" in lateral
    assert "column is called `unnest`" in lateral

    at_field = _hint(_sql(_TS_HITS, "SELECT h.@timestamp FROM (SELECT unnest(hits) h FROM data)"))
    assert "must be double-quoted" in at_field, "the @-quoting error did not get the quoting rule"
    assert "TABLE" not in at_field, "a parser error about `@` was handed the lateral-join lecture"

    struct_key = _hint(_sql(_TS_HITS, "SELECT h.usr FROM (SELECT unnest(hits) h FROM data)"))
    assert "DESCRIBE data" in struct_key
    assert "TABLE" not in struct_key
    assert "double-quoted" not in struct_key

    for unrelated in ("SELEC * FROM data", "SELECT * FROM dat"):
        hint = _hint(_sql(_TS_HITS, unrelated))
        assert _SKELETON in hint, "an unrelated error lost the copyable skeleton"
        assert "TABLE" not in hint, f"{unrelated!r} was handed the lateral-join lecture"
        assert "double-quoted" not in hint
        assert "DESCRIBE data" not in hint


def test_the_clause_is_keyed_off_duckdbs_message_not_off_the_querys_own_text():
    """The four probes above are separable by their own SQL text just as cleanly as by what
    duckdb said, so a dispatch that pattern-matched the QUERY — `", unnest("` means lateral,
    `".@"` means quoting — would pass the whole of it and then go silent on the next lead who"""
    # These two probes assert duckdb's OWN wording on purpose: `_error_note` in `sql.py` keys
    # the extra clause off these strings, case-folded, so a duckdb release that rewords them
    # is a tool regression (the clause silently stops appearing), and this is where it
    # surfaces. Case-folded here too, so the pin is the tool's key and nothing stricter.
    lateral = _sql(_TS_HITS, "SELECT ev.message FROM data, unnest(hits) AS ev")
    assert "candidate bindings" in lateral.stderr.lower(), "this probe stopped producing the lateral-join error"
    lateral_hint = _hint(lateral)
    assert "binds `h` to the TABLE" in lateral_hint, (
        "a lateral join under a different alias lost the lateral-join clause — the clause is "
        "keyed off the query's text, not off duckdb's message"
    )
    assert "column is called `unnest`" in lateral_hint
    assert "double-quoted" not in lateral_hint

    at_field = _sql(_TS_HITS, "SELECT rec.@version FROM (SELECT unnest(hits) rec FROM data)")
    assert 'syntax error at or near "@"' in at_field.stderr.lower(), "this probe stopped being a parser error"
    at_field_hint = _hint(at_field)
    assert "must be double-quoted" in at_field_hint, (
        "an unquoted `@`-field under a different alias lost the quoting rule — the rule is "
        "keyed off the query's text, not off duckdb's message"
    )
    assert "TABLE" not in at_field_hint
    assert "DESCRIBE data" not in at_field_hint

    # The skeleton is unconditional, so both respellings still carry the form that binds.
    assert _SKELETON in lateral_hint
    assert _SKELETON in at_field_hint


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
    hint = _hint(proc)
    assert "columns [host, owner]" in hint
    assert "SELECT * FROM data" in hint
    assert "unnest(hits)" not in hint, "a flat payload was handed the search-hits idiom"
    assert _rows(payload, "SELECT * FROM data") == [{"host": "web-1", "owner": "team.platform"}]


def test_the_tool_prints_its_text_in_a_shell_with_no_locale():
    """Both the epilog and the hints carry an em-dash, and a lead's shell is not always UTF-8:
    a container with no locale set hands Python strict-ASCII streams. The tool reconfigures its
    own stdio, so `--help` and a hint reach the lead as text — not as a `UnicodeEncodeError`
    in place of the very hint that was going to save the next turn."""
    help_ = run_sql_py("--help", env=C_LOCALE_ENV)
    assert help_.returncode == EXIT_OK, help_.stderr
    assert "no wrapper envelope to reach" in " ".join(help_.stdout.split())

    hinted = _sql(_TS_HITS, 'SELECT h."@timestamp" FROM data, unnest(hits) AS h', env=C_LOCALE_ENV)
    assert hinted.returncode == EXIT_QUERY_ERROR, hinted.stderr
    assert "binds `h` to the TABLE" in _hint(hinted)


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
    note keyed on the ARITHMETIC would pass both. These two pull the signals apart."""
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


@pytest.mark.parametrize("payload", ["", "   ", "\n"], ids=["zero-bytes", "spaces", "newline"])
def test_empty_payload_is_an_error_not_an_empty_result(payload):
    """An empty payload file is common (41 of the 640 files in the corpus survey were
    zero bytes), and `jq` exited 0 printing nothing on one — which reads downstream as "the
    entity is absent". This exits 2 and says so, and prints NO rows on stdout, so an empty"""
    proc = _sql(payload, "SELECT count(*) FROM data")
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


def test_the_adapter_emits_the_shape_this_fixture_has(esql):
    """The guard that stops the ES|QL tests above from testing a file instead of the code."""
    fixture = json.loads(esql)
    assert len(fixture["values"]) == 3, "the fixture changed size — this test is no longer at its size"
    raw = {"columns": fixture["columns"], "values": fixture["values"]}
    payload = esql_payload("FROM logs-* | STATS failed = COUNT(*) BY source.ip", raw)

    # Full equality, not shape: the SAME rows in the SAME order with cell `i` under
    # `columns[i]`, so a transpose, a row reversal or a partial re-zip all fail here.
    assert payload["values"] == raw["values"], "the adapter re-shaped rows the wire had sent"
    assert all(isinstance(row, list) for row in payload["values"]), (
        "rows arrived as dicts — the re-zip is back, and the declaration `defender-sql.md` "
        "and sql.py's note teach (`--rows values`) now names a list that is not positional rows"
    )
    assert payload["columns"] == raw["columns"]
    assert payload["row_count"] == len(raw["values"]) == 3

    # The fixture predates the envelope's `query` key, so it is a SUBSET of what the adapter
    # emits, not an equal — the tests above read `columns`/`values`/`row_count` and nothing
    # else. What has to match is the row shape, which is the thing that drifted.
    assert set(fixture) <= set(payload), \
        f"fixture carries keys the adapter does not: {set(fixture) - set(payload)}"
    assert fixture["row_count"] == len(fixture["values"]) == payload["row_count"]


# ---- `->>` binds more loosely than the operators before it ---------------------------------------
# `v[1]->>'$' = 'x' AND v[2]->>'$' = 'y'` parses as `((v[1]->>'$') = 'x' AND v[2]) ->> '$' = 'y'`,
# and `'x' = v[1]->>'$'` as `('x' = v[1]) ->> '$'`: the arrow takes everything written before it as
# its JSON. duckdb then answers `Failed to cast value to numerical: "<value>"` (often a timestamp,
# so it read as a time problem) or a silent, wrong count. The hint's own filter form broke the
# moment a lead added a second condition; 10 calls in the gather runs surveyed by
# experiments/sql-time-contract (step 0) were lost to it.

_UNNESTED_VALUES = "FROM (SELECT unnest(values) v FROM data)"
#: An ES|QL keyword column holding digits (a Windows event code): the value-first form is silently
#: wrong here, where on the fixture's numeric column it happens to be right.
_KEYWORD = json.dumps({
    "columns": [{"name": "event.code", "type": "keyword"}, {"name": "n", "type": "long"}],
    "values": [["4625", 1], ["4624", 2]], "row_count": 2,
})


def test_a_declared_filter_survives_a_second_condition(esql):
    """The positional hint's filter form broke the moment a lead added a second condition
    (#1132). Declared (#1138), a filter is plain SQL over named columns: joined by AND, OR and
    NOT it runs and selects, with no arrow left to misbind."""
    count = "SELECT count(*) AS n FROM data WHERE "
    ip = "\"source.ip\" = '{}'"
    assert _declared(esql, count + f"{ip.format('203.0.113.7')} AND failed = 412") == [{"n": 1}]
    assert _declared(esql, count + f"{ip.format('203.0.113.7')} OR {ip.format('198.51.100.22')}") \
        == [{"n": 2}]
    assert _declared(esql, count + f"NOT {ip.format('203.0.113.7')}") == [{"n": 2}]
    assert _declared(esql, count + f"NOT {ip.format('203.0.113.7')} AND failed > 5") == [{"n": 1}]


def test_a_misbound_arrow_is_refused_with_its_cause_and_a_fix_that_names_no_position(esql):
    """duckdb would name only the symptom (`Failed to cast value to numerical`). The tool refuses
    first and names the cause and the fix — whose example is now a generic JSON column,
    `(col->>'$')`, not a `v[N]` position (#1138 O9) — and, the payload being positional rows,"""
    unwrapped = "v[1]->>'$' = '412' AND v[2]->>'$' = '203.0.113.7'"
    proc = _sql(esql, f"SELECT count(*) AS n {_UNNESTED_VALUES} WHERE {unwrapped}")
    assert_query_error(proc, "the unparenthesised AND was not refused")
    assert "binds more loosely than" in proc.stderr, proc.stderr
    assert "Parenthesise every `->>`" in proc.stderr, proc.stderr
    # The refusal prints the tool's own text and hint, never an echo of the query.
    assert "->>'$'" in proc.stderr, proc.stderr
    assert not re.search(r"v\[\d+\]", proc.stderr), f"the fix still names a position: {proc.stderr!r}"
    assert "--rows values --names columns" in proc.stderr, proc.stderr
    wrapped = "(v[1]->>'$') = '412' AND (v[2]->>'$') = '203.0.113.7'"
    assert _rows(esql, f"SELECT count(*) AS n {_UNNESTED_VALUES} WHERE {wrapped}") == [{"n": 1}]


@pytest.mark.parametrize(("payload", "where", "truth"), [
    ("esql", "v[2]->>'$' = '203.0.113.7' AND v[1]->>'$' = '412'", 1),
    ("esql", "v[2]->>'$' = '203.0.113.7' OR v[1]->>'$' = '3'", 2),
    ("esql", "row_count = 3 AND v[1]->>'$' = '412'", 1),
    ("esql", "NOT v[1]->>'$' = '412'", 2),
    ("keyword", "'4625' = v[1]->>'$'", 1),
    ("keyword", "'4625' <> v[1]->>'$'", 1),
])
def test_a_misbound_arrow_that_would_answer_a_silent_wrong_count_is_refused(
        esql, payload, where, truth):
    """These do not error in duckdb: they answer a confident, wrong count. Refused, not run; the
    same filter with every arrow parenthesised gives the truth."""
    data = esql if payload == "esql" else _KEYWORD
    assert_query_error(_sql(data, f"SELECT count(*) AS n {_UNNESTED_VALUES}, data WHERE {where}"),
                       "a misbound arrow ran")
    wrapped = re.sub(r"(v\[\d\]->>'\$')", r"(\1)", where)
    assert _rows(data, f"SELECT count(*) AS n {_UNNESTED_VALUES}, data WHERE {wrapped}") \
        == [{"n": truth}]


@pytest.mark.parametrize("statement", [
    "CREATE TEMP TABLE r AS SELECT count(*) AS n FROM (SELECT unnest(values) v FROM data) "
    "WHERE v[2]->>'$' = '203.0.113.7' AND v[1]->>'$' = '412'; SELECT * FROM r",
    "PIVOT (SELECT v[1]->>'$' = '412' AND v[2]->>'$' = 'x' AS k FROM (SELECT unnest(values) v "
    "FROM data)) ON k USING count(*)",
])
def test_an_arrow_the_parse_cannot_show_is_refused(esql, statement):
    """duckdb describes only SELECT statements; anything else holding an arrow cannot be checked,
    so it is refused rather than run unchecked."""
    proc = _sql(esql, statement)
    assert_query_error(proc, "an unchecked statement with an arrow ran")
    assert "single SELECT" in proc.stderr, proc.stderr


def test_a_syntax_error_near_an_arrow_gets_duckdbs_own_message(esql):
    """A query duckdb cannot parse has no tree to check either; its own parser error, which names
    the spot, is what the lead needs — not the uncheckable-statement refusal."""
    proc = _sql(esql, 'SELECT data->>"$.[\\"@timestamp\\"]" FROM data')
    assert_query_error(proc, "a syntax error was not reported")
    assert "syntax error" in proc.stderr, proc.stderr
    assert "single SELECT" not in proc.stderr, proc.stderr


def test_a_json_arrow_on_a_json_source_is_not_refused(esql):
    """The refusal keys on the arrow's SOURCE. The doc's projection, a single-condition filter
    with the arrow first, IN, an arrow chained on an arrow, a CAST — the escape the refusal names
    for an expression meant as the JSON — and statements with no arrow at all run."""
    for query in (f"SELECT v[2]->>'$' AS ip {_UNNESTED_VALUES}",
                  f"SELECT count(*) AS n {_UNNESTED_VALUES} WHERE v[2]->>'$' = '203.0.113.7'",
                  f"SELECT count(*) AS n {_UNNESTED_VALUES} WHERE v[2]->>'$' IN ('203.0.113.7')",
                  f"SELECT count(*) AS n {_UNNESTED_VALUES}, data "
                  "WHERE v[2]->>'$' = '203.0.113.7' AND row_count = 3",
                  f"SELECT CAST('{{\"a\": ' || (v[1]->>'$') || '}}' AS JSON)->>'a' AS a {_UNNESTED_VALUES}",
                  "SELECT to_json(columns[1])->>'name' AS c FROM data",
                  "SELECT to_json(columns[1])->>'$'->>'name' AS c FROM data",
                  """SELECT j->>'a' AS a FROM (SELECT '{"a": 1}'::JSON AS j)""",
                  """SELECT '{"a": 1}'->>'a' AS a""",
                  """SELECT (SELECT '{"a": 1}'::JSON)->>'a' AS a""",
                  """SELECT CASE WHEN true THEN '{"a": 1}'::JSON END->>'a' AS a""",
                  """SELECT coalesce(NULL, '{"a": 1}'::JSON)->>'a' AS a""",
                  """SELECT '{"a": {"b": 1}}'::JSON->'a'->>'b' AS b""",
                  "DESCRIBE data",
                  "SUMMARIZE data"):
        proc = _sql(esql, query)
        assert proc.returncode == EXIT_OK, (query, proc.stderr)


def test_an_operator_expression_meant_as_the_json_is_refused_and_its_cast_runs(esql):
    """The parse keeps no parentheses, so `('{' || x || '}')->>'a'` reads exactly like a misbound
    `'{' || x || '}'->>'a'`; it is refused, and the CAST the refusal names runs."""
    concat = "'{\"a\": ' || (v[1]->>'$') || '}'"
    proc = _sql(esql, f"SELECT ({concat})->>'a' AS a {_UNNESTED_VALUES}")
    assert_query_error(proc, "an operator expression as an arrow's source ran")
    assert "CAST(<expression> AS JSON)" in proc.stderr, proc.stderr
    assert _rows(esql, f"SELECT CAST({concat} AS JSON)->>'a' AS a {_UNNESTED_VALUES}") == [
        {"a": "412"}, {"a": "9"}, {"a": "3"}]
