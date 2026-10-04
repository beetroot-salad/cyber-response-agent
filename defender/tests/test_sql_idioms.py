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
    {columns, values, row_count}  (ES|QL)       -> declared: `--rows values --names columns`
                                                   makes each name a column (#1138)
    flat object                                 -> one row, its keys are the columns
    bare array                                  -> one row per element
    empty / not JSON                            -> input error (exit 2), NOT an empty result

duckdb lives in the `runtime` extra. CI syncs it (every test job runs `uv sync --extra dev
--extra runtime`), so these guards do block a merge; a dev-only checkout skips exactly the
tests that run a QUERY — the tool imports duckdb lazily, so `--help`, the adapter binding
and the doc census need nothing and run everywhere.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
from markdown_it import MarkdownIt

from defender._io import read_text_utf8
from defender.scripts.adapters.elastic_adapter import esql_payload
from defender.tests._by_path import DEFENDER
from defender.tests._defender_sql import (
    EXIT_INPUT_ERROR,
    EXIT_OK,
    EXIT_QUERY_ERROR,
    SQL_PY,
    assert_query_error,
    run_sql_py,
)
from defender.tests._sql_warm import run_sql_warm
from defender.tests._locale import C_LOCALE_ENV

_DOC = DEFENDER / "skills" / "gather" / "defender-sql.md"
_SKILLS = DEFENDER / "skills"

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


@pytest.fixture(scope="module")
def doc() -> str:
    return read_text_utf8(_DOC)


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
    """What the TOOL added to a query error, and nothing duckdb said.

    stderr carries duckdb's own message and its `LINE 1:` echo of the query before the
    tool's `hint:` — so a negative assertion ("the other fixture's columns are not named")
    made against the whole of stderr is really made against the query text and duckdb's
    prose, and reddens on a reword that has nothing to do with the hint."""
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
    `test_the_adapter_emits_the_shape_this_fixture_has`, which is what makes "a change to the
    ES|QL adapter's output shape breaks this" true rather than hopeful.

    Declared (#1138 O1), the rows ARE the table: one row per row, one column per name, in the
    names' order. Unflagged the payload is one object and so one row (#1138 O6: unchanged) —
    the envelope's own `row_count` is still readable that way."""
    assert set(json.loads(esql)) >= {"columns", "row_count", "values"}, "the real fixture changed shape"
    assert _declared(esql, "SELECT count(*) AS n FROM data") == [{"n": 3}]
    assert [(r["column_name"], r["column_type"]) for r in _declared(esql, "DESCRIBE data")] == [
        ("failed", "BIGINT"), ("source.ip", "VARCHAR")]
    assert _rows(esql, "SELECT row_count FROM data") == [{"row_count": 3}]


def test_esql_rows_are_queried_by_name_once_declared(esql):
    """The trap the positional recipe lived in: `unnest(values)` yields a POSITIONAL `JSON[]`,
    so the struct spelling `v."source.ip"` is a Binder Error — still, unflagged — and the only
    way through was `v[N]->>'$'` plus a cast, because `->>'$'` is TEXT and `'412' < '9'` is true
    lexically. Declared, the column is addressed by its name and `failed` is a number the
    payload sent as a number: no position, no arrow, no cast (#1138 O1)."""
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
    mean`), and a paragraph appended to every failure buries the one sentence that applies.
    So the shape skeleton is unconditional — it is what stops the NEXT query failing — while
    the prose clause is keyed to what duckdb actually said. An unrelated error gets the
    skeleton and nothing else: no lateral-join lecture, no quoting rule, no DESCRIBE."""
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
    `".@"` means quoting — would pass the whole of it and then go silent on the next lead who
    spelled the same mistake differently.

    So: the same two error CLASSES, respelled. A different lateral alias (`ev`, not `h`), and
    a different `@`-field under a different subquery alias (`rec.@version`, not `h.@timestamp`,
    on a field this payload does not even carry). Each must get the SAME clause as its sibling
    above — which only a dispatch reading duckdb's message can do, because the query text it
    would have keyed on is gone."""
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


@pytest.mark.parametrize("payload", ["", "   ", "\n"], ids=["zero-bytes", "spaces", "newline"])
def test_empty_payload_is_an_error_not_an_empty_result(payload):
    """An empty payload file is common (41 of the 640 files in the corpus survey were
    zero bytes), and `jq` exited 0 printing nothing on one — which reads downstream as "the
    entity is absent". This exits 2 and says so, and prints NO rows on stdout, so an empty
    result set can never be confused with a missing observation. The zero-byte file and the
    whitespace-only file are different inputs on stdin; both must take this branch."""
    proc = _sql(payload, "SELECT count(*) FROM data")
    assert proc.returncode == EXIT_INPUT_ERROR
    assert proc.stdout == ""
    assert "no input on stdin" in proc.stderr
    assert "NOT an empty result set" in proc.stderr


def test_the_doc_teaches_the_exit_codes_the_tests_pin(doc):
    """The exit codes in `_defender_sql` are literals BECAUSE they are what the doc teaches;
    the spawn tests hold the tool to them, and this holds the doc to them, so neither the
    tool nor the sentence can renumber alone.

    #1138's exit table moved one thing: a wrong `--rows`/`--names` declaration is a `1`, the
    lead's mistake to fix like a query error (and a lesson for the pitfalls curator), while `2`
    stays the payload that never arrived or is not JSON. So the paragraph's `1` must name the
    declaration beside the query error, and its `2` the payload — read clause by clause, the
    digits pinned and the prose around them free."""
    paragraph = next((p for p in re.split(r"\n\s*\n", doc)
                      if "exit code" in p.lower() and re.search(r"`\d+`\s*=", p)), None)
    assert paragraph, "the doc no longer has an exit-code paragraph"
    marks = list(re.finditer(r"`(\d+)`\s*=\s*", paragraph))
    clauses = {
        int(m.group(1)): paragraph[m.end():marks[i + 1].start() if i + 1 < len(marks) else None]
        for i, m in enumerate(marks)
    }
    assert set(clauses) == {EXIT_QUERY_ERROR, EXIT_INPUT_ERROR}, clauses
    assert "query error" in clauses[EXIT_QUERY_ERROR], clauses
    assert "--rows" in clauses[EXIT_QUERY_ERROR] or "--names" in clauses[EXIT_QUERY_ERROR], (
        f"the doc's `1` does not cover a wrong declaration: {clauses[EXIT_QUERY_ERROR]!r}")
    assert "payload" in clauses[EXIT_INPUT_ERROR], clauses


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


# ------------------------------------------ O5: every unnest a lead is shown names a live shape


#: The one key `unnest` can be pointed at on a lead-facing surface: `hits`, the search-hits
#: shape's rows. ES|QL's `values` left the list with #1138 — positional rows are DECLARED
#: (`--rows values --names columns`), never unnested — and no adapter emits a wrapper, so
#: `unnest(result.hits)`, the recipe of a code path that is gone, and `unnest(values)`, the
#: recipe #1138 retired, are not spellings to hunt for but simply not this one. (A declared
#: list column is taught as `list_contains(...)`, or `unnest` named bare: an `unnest(<column>)`
#: on these surfaces is outside the whitelist.)
_LIVE_SHAPES = {"hits"}

#: Case-insensitive with optional space before the paren: SQL keywords are, and the recipes a
#: curator records are LLM-written, which uppercases them as often as not.
_UNNEST_ARG = re.compile(r"unnest\s*\(\s*([^)]*?)\s*\)", re.IGNORECASE)


def _unnest_args(text: str) -> set[str]:
    """What each `unnest(...)` on `text` reaches, with the table's own qualifier stripped —
    `unnest(data.hits)` reaches `hits`; `unnest(result.hits)` reaches a wrapper that is not
    there, and stays spelled as it is so the failure names it."""
    return {re.sub(r"^data\.", "", arg, flags=re.IGNORECASE) for arg in _UNNEST_ARG.findall(text)}


#: The engine `bin/defender-sql` runs: its source carries the help epilog and the hints.
_SQL_ENGINE = DEFENDER / "runtime" / "sql_engine" / "sql.py"


def _lead_surfaces() -> list[Path]:
    """Everything a gather lead reads or runs when it writes SQL over a payload: the tool
    itself, and every skill doc — `defender-sql.md`, the adapter contract, the query
    templates, and each system's recorded execution notes, which is where a curator would
    write a recipe down. Enumerated, not hand-listed, so a new doc is censused on arrival."""
    return [_SQL_ENGINE, *sorted(_SKILLS.rglob("*.md"))]


def test_every_unnest_on_a_lead_facing_surface_names_a_live_shape():
    """A census by whitelist rather than by the spelling of the one dead recipe: on every
    surface, whatever `unnest(...)` is pointed at must be a key an adapter actually emits.
    This is what keeps `unnest(result.hits)` — and any wrapper-reaching spelling nobody has
    written yet — from coming back through a doc, a query template, or a system's execution
    notes, none of which a three-file list would have watched."""
    # Keyed by the path, not the basename: every system has its own `execution.md`, and a
    # basename key would keep only the last one read.
    seen = {
        str(path.relative_to(DEFENDER)): _unnest_args(read_text_utf8(path))
        for path in _lead_surfaces()
    }
    dead = {name: args - _LIVE_SHAPES for name, args in seen.items() if args - _LIVE_SHAPES}
    assert not dead, f"a lead-facing surface unnests something no adapter emits: {dead}"
    # Paired control: the census really covered the surfaces that teach the idioms, and between
    # them they teach the live shape — a zero above cannot come from reading nothing.
    teaching = {name for name, args in seen.items() if args}
    assert {
        "runtime/sql_engine/sql.py", "skills/gather/defender-sql.md", "skills/connect/adapter.md",
    } <= teaching, teaching
    assert set().union(*seen.values()) == _LIVE_SHAPES


def test_the_help_epilog_the_lead_actually_prints_is_clean_too():
    """The census above reads `sql.py` as a FILE. What a lead reads is `--help`, and a recipe
    reintroduced through argparse's `%(prog)s` interpolation is not in the source text at all.
    So run the program and read its output, under the same whitelist. The paired control is
    the live idiom: the epilog really does hand the lead a hits query, so a clean census here
    cannot come from an epilog that says nothing."""
    proc = run_sql_py("--help")
    assert proc.returncode == EXIT_OK, proc.stderr
    printed = proc.stdout + proc.stderr
    assert _unnest_args(printed) == {"hits"}, f"`--help` unnests something no adapter emits: {printed!r}"
    # argparse reflows the epilog at the terminal width, so the control is read unwrapped.
    unwrapped = " ".join(printed.split())
    assert "unnest(hits) h FROM data" in unwrapped
    assert "no wrapper envelope to reach" in unwrapped


def test_the_dead_recipe_stays_dead():
    """Why the census above is worth having: the recipe does not merely look stale, it FAILS.
    Pinning the failure keeps anyone from reintroducing it on the strength of an old doc."""
    proc = _sql(_HITS, "SELECT count(*) FROM (SELECT unnest(result.hits) h FROM data)")
    assert_query_error(proc, "the dead recipe ran")
    # ...and fails for the reason the census rests on: `result` is the identifier duckdb
    # could not resolve, because no adapter emits that wrapper. Any wording quotes the
    # name it could not find; read before the `LINE 1:` echo of the query, which would
    # carry `result` for ANY failure.
    message = proc.stderr.partition("\nLINE ")[0]
    assert '"result"' in message, proc.stderr
    # and the live spelling, on the same payload, works
    assert _rows(_HITS, "SELECT count(*) AS n FROM (SELECT unnest(hits) h FROM data)") \
        == [{"n": 3}]


# ------------------------------------ doc binding: what defender-sql.md prints, run verbatim


#: A struct-style field access on an ES|QL `values` row — `v.host`, `v."source.ip"`. The
#: placeholder `v.<field>` the doc uses to NAME the failing idiom is deliberately not matched:
#: what is banned is a concrete field spelled after `v.`, which is a recipe rather than a
#: citation. `(?<![A-Za-z0-9_])` keeps a hostname or a version string from counting.
_STRUCT_ACCESS_ON_V = re.compile(r"(?<![A-Za-z0-9_])v\s*\.\s*[A-Za-z_\"]", re.IGNORECASE)

#: The lateral spelling, `FROM data, unnest(hits) [AS] h` — the one that looks right and binds
#: `h` to the TABLE. Case-insensitive for the same reason as `_UNNEST_ARG`.
_LATERAL_FORM = re.compile(r"FROM\s+data\s*,\s*unnest\s*\(\s*hits\s*\)", re.IGNORECASE)


#: A line that LOOKS like a fence edge to someone reading the raw file.
_FENCE_EDGE = re.compile(r"^[ \t]*(`{3,}|~{3,})", re.M)
#: The info string names sql — ` ```sql`, ` ```SQL {.x}`, ` ```sql{.x}` — and not ` ```sqlite`.
_SQL_INFO = re.compile(r"sql(?![\w-])", re.I)


def _sql_fences(text: str) -> list[str]:
    """The doc's sql-tagged fences — what a lead copies, as opposed to what the prose discusses.

    A CommonMark parse, not a regex: tildes, four-backtick fences, a space before the tag,
    ` ```SQL`, ` ```sql {.x}` are all the same fence to a renderer and so to this scanner, and
    ` ```sqlite` is not. A hand-rolled pattern tolerated a list of spellings and missed the
    rest, which is how a retagged fence carrying a banned form went unscanned (#1059).

    The doc's reader is not a renderer, though — the gather subagent reads it as raw text and
    copies what looks like a fence. A fence CommonMark does not see (under an HTML wrapper
    with no blank line, indented four spaces) is still copyable, so the parse is checked
    against the raw text: every fence-looking line must lie inside a fence the parser found
    (as one of its edges, or nested in its body). The scanner then fails loudly on the fence
    it cannot read, instead of skipping it."""
    fences = [tok for tok in MarkdownIt().parse(text) if tok.type == "fence"]
    spans = [tok.map for tok in fences]  # [first line, one past last), 0-based
    lines = text.split("\n")
    stray = [
        f"{n + 1}: {line.strip()}" for n, line in enumerate(lines)
        if _FENCE_EDGE.match(line) and not any(a <= n < b for a, b in spans)
    ]
    assert not stray, (
        "fence-looking lines the markdown parser does not read as a fence — a reader "
        f"would copy them and this scanner cannot see them: {stray}"
    )
    return [tok.content for tok in fences if _SQL_INFO.match(tok.info.strip())]


#: A `<field>`-style placeholder — a template for the lead to fill, not a query to run.
_PLACEHOLDER = re.compile(r"<[A-Za-z_][\w .-]*>")
_QUOTED_NAME = re.compile(r'"([^"]+)"')
#: The tracked fixture's names, as the declaration makes them columns.
_FIXTURE_NAMES = {"failed", "source.ip"}
#: #1138 O1's witness filter: a dotted name compared as text AND a number compared as a number.
_O1_FILTER = re.compile(r'"source\.ip"\s*=\s*\'203\.0\.113\.7\'\s+AND\s+failed\s*>\s*9\b', re.I)
_POSITIONAL_RECIPE = re.compile(r"v\s*\[\s*\d+\s*\]\s*->>")


def _declared_fences(doc: str) -> list[str]:
    """The doc's copyable SQL written for the DECLARED ES|QL table: an sql fence that names
    only the tracked fixture's columns (double-quoted, as a dotted name must be), holds no
    placeholder to fill and no `unnest`. A fence for another table (a list column, a JSON
    column) names a column the fixture does not have and is not one of these."""
    fences = []
    for fence in _sql_fences(doc):
        quoted = set(_QUOTED_NAME.findall(fence))
        if (quoted and quoted <= _FIXTURE_NAMES and not _PLACEHOLDER.search(fence)
                and "unnest" not in fence.lower()):
            fences.append(fence.strip())
    return fences


def _typed_oracle(payload_doc: dict, query: str) -> list[dict]:
    """What `query` answers over the fixture's rows in a table typed BY HAND the way #1138's
    rule types them — `failed` BIGINT (every cell a JSON integer), `source.ip` VARCHAR (every
    cell a string) — computed in-process, independently of the tool."""
    duckdb = pytest.importorskip("duckdb")
    con = duckdb.connect(":memory:")
    con.execute('CREATE TABLE data ("failed" BIGINT, "source.ip" VARCHAR)')
    con.executemany("INSERT INTO data VALUES (?, ?)", payload_doc["values"])
    cursor = con.execute(query)
    names = [d[0] for d in cursor.description]
    return [dict(zip(names, record, strict=True)) for record in cursor.fetchall()]


def test_the_docs_declared_examples_run_and_answer_what_a_typed_table_answers(doc, esql):
    """`defender-sql.md`'s copyable SQL for positional rows is written against the DECLARED
    table (#1138 O9): each such fence, run as written under `--rows values --names columns` over
    the real fixture, exits 0 and answers exactly what the same SQL answers over a table typed
    by hand from the fixture's JSON values — so the doc cannot teach a query that runs but
    answers wrong (a lexical comparison, a text sum). One of them is O1's witness, the dotted
    name compared as text AND the count compared as a number, and it selects the 412 row."""
    for flag in (r"--rows[ =]values", r"--names[ =]columns"):
        assert re.search(flag, doc), "the doc does not show the declaration ES|QL is queried under"
    fences = _declared_fences(doc)
    assert fences, "the doc has no runnable SQL fence for the declared ES|QL table"
    payload_doc = json.loads(esql)
    for fence in fences:
        answer = _declared(esql, fence)
        assert answer == _typed_oracle(payload_doc, fence), f"the doc's fence answers wrong: {fence!r}"

    witness = [f for f in fences if _O1_FILTER.search(f)]
    assert witness, "no doc fence filters `\"source.ip\" = '203.0.113.7' AND failed > 9`"
    for fence in witness:
        answer = _declared(esql, fence)
        assert len(answer) == 1, (fence, answer)
        assert 412 in answer[0].values(), (fence, answer)


def test_the_doc_no_longer_teaches_the_positional_recipe(doc):
    """The recipe the declaration replaced is gone from the doc (#1138 O9): no `v[N]->>'$'`, no
    `unnest(values)`, no `::BIGINT` over an unpacked position — a number the payload sent as a
    number needs no cast once declared — and no copyable fence reaches into a `values` row.
    The arrow-precedence rule stays (it is about JSON columns and JSON sources, not positions)."""
    assert not _POSITIONAL_RECIPE.search(doc), "the doc still teaches `v[N]->>`"
    assert not re.search(r"unnest\s*\(\s*values\s*\)", doc, re.I), "the doc still unnests `values`"
    assert "(v[3]->>'$')::BIGINT" not in doc, "the doc still teaches the positional cast"
    for fence in _sql_fences(doc):
        assert _STRUCT_ACCESS_ON_V.search(fence) is None, f"a copyable fence cannot run: {fence!r}"
    assert "binds more loosely than" in doc, "the doc dropped WHY `->>` needs parentheses"


def test_the_docs_hits_idiom_is_literal_and_runs(doc):
    """The doc's search-hits binding, same treatment: present as a literal, then executed
    with only its `<field>`/`<other>`/`<value>` placeholders filled — no alias added that
    the doc's own template does not carry."""
    idiom = ("SELECT h.<field> FROM (SELECT unnest(hits) h FROM data) "
             "WHERE h.<other> = '<value>'")
    assert idiom in doc, "the doc's search-hits idiom changed"

    # The lateral form is the one that looks right and binds `h` to the TABLE. It may appear
    # ONLY as the named trap, never as something a lead copies: no fence carries it, and every
    # occurrence sits inside the sentence that rules it out.
    fences = _sql_fences(doc)
    for fence in fences:
        assert _LATERAL_FORM.search(fence) is None, (
            f"a copyable fence hands back the lateral form, which does not bind: {fence!r}"
        )
    assert idiom.strip() in [f.strip() for f in fences], "the subquery form left the copyable fences"
    for found in _LATERAL_FORM.finditer(doc):
        window = doc[max(0, found.start() - 250):found.start() + 350]
        assert any(marker in window for marker in (
            "does not do what it looks like", "names the TABLE", "does not resolve",
        )), "the lateral form appears without the caveat that it does not bind"

    runnable = _fill(idiom, {
        "h.<field>": "h.user", "h.<other>": "h.host", "<value>": "web-1",
    })
    assert _rows(_HITS, runnable) == [{"user": "alice"}, {"user": "bob"}]


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
    `(col->>'$')`, not a `v[N]` position (#1138 O9) — and, the payload being positional rows,
    the declaration that makes the arrow unnecessary (O6). The same query parenthesised runs
    and selects: `_arrow_refusal` is #1132's backstop and stays."""
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
