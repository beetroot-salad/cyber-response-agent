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

duckdb lives in the `runtime` extra. CI syncs it (every test job runs `uv sync --extra dev
--extra runtime`), so these guards do block a merge; a dev-only checkout skips exactly the
tests that run a QUERY — the tool imports duckdb lazily, so `--help`, the adapter binding
and the doc census need nothing and run everywhere.
"""
from __future__ import annotations

import importlib.util
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
    SQL_PY as _SQL_PY,
    run_sql_py as _run_sql_py,
)
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

#: `find_spec` asks the interpreter `run_sql_py` spawns (`sys.executable`), so the answer
#: is the child's, and nothing is imported at collection.
_HAS_DUCKDB = importlib.util.find_spec("duckdb") is not None


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
    if not _HAS_DUCKDB:
        pytest.skip("duckdb (the `runtime` extra) is not installed — no query can run")
    return _run_sql_py(query, stdin=payload, env=env)


def _rows(payload: str, query: str) -> list:
    proc = _sql(payload, query)
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
    ES|QL adapter's output shape breaks this" true rather than hopeful."""
    assert set(json.loads(esql)) >= {"columns", "row_count", "values"}, "the real fixture changed shape"
    assert _rows(esql, "SELECT row_count FROM data") == [{"row_count": 3}]
    assert _rows(esql, "SELECT count(*) AS n FROM (SELECT unnest(values) v FROM data)") \
        == [{"n": 3}]


def test_esql_values_are_positional_json_not_a_struct(esql):
    """The trap: `unnest(values)` yields a POSITIONAL `JSON[]`, not the named struct
    `unnest(hits)` yields, so `v.<field>` — the idiom that is right one shape over — is a
    Binder Error here. The positional spelling is the paired positive control, and the
    `::BIGINT` cast is why the doc insists on it: `->>'$'` is TEXT, so `'412' < '9'` is true
    lexically and false numerically."""
    struct_idiom = _sql(
        esql,
        'SELECT count(*) FROM (SELECT unnest(values) v FROM data) WHERE v."source.ip" = \'x\'',
    )
    # The exit code is the contract; duckdb's own wording of WHY (`not a struct` today) is
    # not, and the paired positive control below is what proves the failure is the idiom's.
    assert struct_idiom.returncode == EXIT_QUERY_ERROR

    assert _rows(
        esql,
        "SELECT count(*) AS n FROM (SELECT unnest(values) v FROM data) "
        "WHERE v[2]->>'$' = '203.0.113.7'",
    ) == [{"n": 1}]
    assert _rows(
        esql,
        "SELECT sum((v[1]->>'$')::BIGINT) AS failed FROM (SELECT unnest(values) v FROM data)",
    ) == [{"failed": 424}]
    lexical = "SELECT count(*) AS n FROM (SELECT unnest(values) v FROM data) WHERE {} < {}"
    assert _rows(esql, lexical.format("v[1]->>'$'", "'9'")) == [{"n": 2}]
    assert _rows(esql, lexical.format("(v[1]->>'$')::BIGINT", "9")) == [{"n": 1}]


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
    assert proc.returncode == EXIT_QUERY_ERROR
    assert _rows(payload, "DESCRIBE data")


# ------------------------------------------- O2: a wrong-shape query is told the real shape


def _positions(payload_doc: dict) -> str:
    """The positional map the ES|QL hint must print for THIS payload, from its own `columns`."""
    return "Positions: " + ", ".join(
        f"{i + 1}={c['name']}" for i, c in enumerate(payload_doc["columns"])
    )


#: The two clauses of a hint that are DERIVED from the payload in hand. "The other payload's
#: names are absent" is asserted of these, not of the idiom prose around them.
_POSITIONS_CLAUSE = re.compile(r"Positions: .*?\.(?=\s)")
_COLUMNS_CLAUSE = re.compile(r"columns \[[^\]]*\]")


def _clause(hint: str, pattern: re.Pattern[str]) -> str:
    found = pattern.search(hint)
    assert found, f"no {pattern.pattern!r} clause in the hint: {hint!r}"
    return found.group(0)


def test_query_error_on_esql_shape_hint_gives_the_positional_map(esql):
    """Struct access on ES|QL `values` fails, and the hint names the EXACT position of each
    field FOR THIS payload — grounded in the fixture's own `columns`, not a generic table.

    The runnable form is taken OUT of the hint text and executed, so the hint cannot hand
    back a recipe that does not run: `<value>` is the only thing substituted."""
    payload_doc = json.loads(esql)
    proc = _sql(
        esql,
        'SELECT count(*) FROM (SELECT unnest(values) v FROM data) WHERE v."source.ip" = \'x\'',
    )
    assert proc.returncode == EXIT_QUERY_ERROR
    hint = _hint(proc)
    assert "POSITIONAL JSON array" in hint
    assert _positions(payload_doc) in hint

    form = "v[2]->>'$' = '<value>'"
    assert form in hint
    runnable = _fill(form, {"<value>": str(payload_doc["values"][0][1])})
    assert _rows(
        esql,
        f"SELECT count(*) AS n FROM (SELECT unnest(values) v FROM data) WHERE {runnable}",
    ) == [{"n": 1}]


def test_the_esql_positional_map_is_derived_from_each_payloads_own_columns():
    """The test above reads ONE payload, so a hint holding a memorized `1=failed, 2=source.ip`
    would satisfy it while being a lie about every other ES|QL payload a lead is handed. This
    is a different payload — three columns, none of them the fixture's — and the map has to
    follow it, with the fixture's own positions nowhere in sight."""
    payload_doc = {
        "columns": [{"name": "host.name", "type": "keyword"},
                    {"name": "bytes", "type": "long"},
                    {"name": "user", "type": "keyword"}],
        "values": [["web-1", 4096, "alice"], ["db-1", 512, "bob"]],
        "row_count": 2,
    }
    payload = json.dumps(payload_doc)
    proc = _sql(
        payload,
        'SELECT count(*) FROM (SELECT unnest(values) v FROM data) WHERE v."host.name" = \'x\'',
    )
    assert proc.returncode == EXIT_QUERY_ERROR
    hint = _hint(proc)
    assert "POSITIONAL JSON array" in hint
    positions = _clause(hint, _POSITIONS_CLAUSE)
    assert positions == _positions(payload_doc) + ".", (
        "the positional map did not follow this payload's own `columns`"
    )
    for fixture_column in ("failed", "source.ip"):
        assert fixture_column not in positions, (
            "the hint carried the tracked fixture's columns into an unrelated payload — it is "
            "a memorized constant, not a map of the payload in hand"
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
    assert 'syntax error at or near "@"' in at_field.stderr, "this probe stopped being a parser error"
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
    help_ = _run_sql_py("--help", env=C_LOCALE_ENV)
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
        "rows arrived as dicts — the re-zip is back, and `defender-sql.md` plus sql.py's "
        "ES|QL hint now teach an idiom that cannot run"
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


#: The two keys `unnest` can be pointed at, one per payload shape that HAS rows to unnest:
#: `hits` (search-hits) and `values` (ES|QL). No adapter emits any other list to unnest, and
#: no adapter emits a wrapper — so `unnest(result.hits)`, the recipe of a code path that is
#: gone, is not a spelling to hunt for but simply not one of these two.
_LIVE_SHAPES = {"hits", "values"}

#: Case-insensitive with optional space before the paren: SQL keywords are, and the recipes a
#: curator records are LLM-written, which uppercases them as often as not.
_UNNEST_ARG = re.compile(r"unnest\s*\(\s*([^)]*?)\s*\)", re.IGNORECASE)


def _unnest_args(text: str) -> set[str]:
    """What each `unnest(...)` on `text` reaches, with the table's own qualifier stripped —
    `unnest(data.hits)` reaches `hits`; `unnest(result.hits)` reaches a wrapper that is not
    there, and stays spelled as it is so the failure names it."""
    return {re.sub(r"^data\.", "", arg, flags=re.IGNORECASE) for arg in _UNNEST_ARG.findall(text)}


def _lead_surfaces() -> list[Path]:
    """Everything a gather lead reads or runs when it writes SQL over a payload: the tool
    itself, and every skill doc — `defender-sql.md`, the adapter contract, the query
    templates, and each system's recorded execution notes, which is where a curator would
    write a recipe down. Enumerated, not hand-listed, so a new doc is censused on arrival."""
    return [_SQL_PY, *sorted(_SKILLS.rglob("*.md"))]


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
    # them they teach both live shapes — a zero above cannot come from reading nothing.
    teaching = {name for name, args in seen.items() if args}
    assert {
        "scripts/gather_tools/sql.py", "skills/gather/defender-sql.md", "skills/connect/adapter.md",
    } <= teaching, teaching
    assert set().union(*seen.values()) == _LIVE_SHAPES


def test_the_help_epilog_the_lead_actually_prints_is_clean_too():
    """The census above reads `sql.py` as a FILE. What a lead reads is `--help`, and a recipe
    reintroduced through argparse's `%(prog)s` interpolation is not in the source text at all.
    So run the program and read its output, under the same whitelist. The paired control is
    the live idiom: the epilog really does hand the lead a hits query, so a clean census here
    cannot come from an epilog that says nothing."""
    proc = _run_sql_py("--help")
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
    assert proc.returncode == EXIT_QUERY_ERROR
    # ...and fails for the reason the census rests on — no adapter emits a `result` wrapper,
    # so the column is not there to unnest — not for some other query error.
    columns = [row["column_name"] for row in _rows(_HITS, "DESCRIBE data")]
    assert "result" not in columns, columns
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


def _sql_fences(text: str) -> list[str]:
    """The doc's sql-tagged fences — what a lead copies, as opposed to what the prose discusses.

    A CommonMark parse, not a regex: tildes, four-backtick fences, a space before the tag,
    ` ```SQL`, ` ```sql {.x}` are all the same fence to a renderer and so to this scanner, and
    ` ```sqlite` is not. A hand-rolled pattern tolerated a list of spellings and missed the
    rest, which is how a retagged fence carrying a banned form went unscanned (#1059)."""
    return [
        tok.content for tok in MarkdownIt().parse(text)
        if tok.type == "fence" and tok.info.lower().split()[:1] == ["sql"]
    ]


def test_the_docs_esql_example_is_literal_and_runs(doc, esql):
    """`defender-sql.md`'s ES|QL example, asserted present as a LITERAL and then executed —
    the same string, unedited — against the real fixture. Bound to the string rather than
    parsed out of the fence, so an edit to the doc's recipe must come here and be re-run
    rather than quietly redefining what is tested."""
    example = "SELECT v[2]->>'$' FROM (SELECT unnest(values) v FROM data)"
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

    rows = _rows(esql, example)
    # One unaliased column per row, so the KEY is duckdb's generated name for the expression
    # (`(v[2] ->> '$')` today) and is not part of this contract across a `duckdb>=1.5,<2`
    # bump. The values are: position 2 is `source.ip`, in the fixture's own row order.
    assert [list(row.values()) for row in rows] == [
        ["203.0.113.7"], ["198.51.100.22"], ["203.0.113.40"],
    ]


def test_the_docs_bigint_cast_rule_is_literal_and_runs(doc, esql):
    """The doc's cast rule, the same way: the literal `(v[3]->>'$')::BIGINT` must be in the
    file and must PARSE AND RUN as written (position 3 is past this fixture's two columns, so
    it yields NULL rather than an error — the cast itself is what is under test). The same
    cast at a position the fixture has gives the real number, and the uncast comparison gives
    the wrong one, which is the claim the rule exists to make — executed, because a rule the
    doc states and a doc that quietly retracts it are told apart by what runs, not by prose."""
    rule = "(v[3]->>'$')::BIGINT"
    assert rule in doc, "the doc's ::BIGINT cast rule changed"
    assert "returns **TEXT**" in doc, "the doc no longer says what `->>'$'` hands back"
    assert "lexical" in doc.lower(), "the doc dropped WHY the cast is required"

    unnested = "FROM (SELECT unnest(values) v FROM data)"
    assert _rows(esql, f"SELECT {rule} AS n {unnested}") == [{"n": None}] * 3

    at_real_position = rule.replace("v[3]", "v[1]")
    assert _rows(esql, f"SELECT {at_real_position} AS failed {unnested}") == [
        {"failed": 412}, {"failed": 9}, {"failed": 3},
    ]
    assert _rows(esql, f"SELECT count(*) AS n {unnested} WHERE {at_real_position} < 9") \
        == [{"n": 1}]
    assert _rows(esql, f"SELECT count(*) AS n {unnested} WHERE v[1]->>'$' < '9'") \
        == [{"n": 2}], "the uncast comparison is supposed to be lexical — that is the point"


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
