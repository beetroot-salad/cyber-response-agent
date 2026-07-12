"""The judge's SQL idioms must actually RUN against the payload shapes it will meet.

`defender-sql` was fully plumbed but dormant — 0 of 64 query templates used it, no
`execution.md` recorded a recipe — and its documented example (`unnest(result.hits)` over
a `{system, endpoint, args, result}` envelope) matched NO adapter's output: there is no
`result` key anywhere in the corpus. That recipe would have failed the first time the
judge ran it. This file is the guard: it executes the idioms the judge's prompts teach,
through the real `defender-sql`, against the real payload shapes.

Shapes are from a survey of all 640 payloads under `gather_raw/l-*/` in the repo:

    241x  {index, total, returned, truncated, hits}   -> unnest(hits)
    ~230x flat object (cmdb / identity / ...)         -> SELECT * FROM data   (one row)
     31x  {columns, row_count, values}   (ES|QL)      -> unnest(values)
     12x  bare array of documents                     -> SELECT ... FROM data
     41x  EMPTY file      -> input error (exit 2), NOT an empty result set
     25x  markdown        -> input error; the judge must use read_file(pattern=)

The last two are why the prompt says an empty or non-JSON payload is *silent*, never
*absent*: `defender-sql` fails loudly where `jq` exited 0 on an empty file, which a
refute primitive would have read as "the projected entity is missing".
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("duckdb")

_DEFENDER = Path(__file__).resolve().parents[1]
_SQL_PY = _DEFENDER / "scripts" / "gather_tools" / "sql.py"
_JUDGE = _DEFENDER / "learning" / "pipeline" / "judge"

# The one real, git-tracked gather_raw payload in the repo (the ES|QL shape).
_REAL_ESQL = (
    _DEFENDER / "evals" / "scenarios_lead" / "underfold-sshd-narrowing"
    / "run" / "run-underfold-001" / "gather_raw" / "l-001" / "0.json"
)


def _sql(payload: str, query: str) -> subprocess.CompletedProcess:
    """Run the real `defender-sql` over `payload` on stdin. No shim, no DEFENDER_DIR."""
    return subprocess.run(
        [sys.executable, str(_SQL_PY), query],
        input=payload, capture_output=True, text=True, timeout=60,
    )


def _rows(payload: str, query: str) -> list:
    proc = _sql(payload, query)
    assert proc.returncode == 0, f"defender-sql failed: {proc.stderr}"
    return json.loads(proc.stdout)


# ---------------------------------------------------------------------------
# the four JSON shapes the judge will meet, with the idiom its prompt teaches
# ---------------------------------------------------------------------------

_ELASTIC = json.dumps({
    "index": "logs-*", "total": 9189, "returned": 3, "truncated": True,
    "hits": [
        {"user": "alice", "host": "web-1"},
        {"user": "bob", "host": "web-1"},
        {"user": "alice", "host": "db-1"},
    ],
})


def test_elastic_envelope_unnest_hits():
    """`{index,total,returned,truncated,hits}` — the modal shape (241/640). The prompt's
    worked example is a count over `unnest(hits)` with a WHERE on a hit field."""
    rows = _rows(_ELASTIC, "SELECT count(*) AS n FROM (SELECT unnest(hits) h FROM data) WHERE h.user = 'alice'")
    assert rows == [{"n": 2}]


def test_elastic_envelope_truncation_columns_are_readable():
    """The `truncated` guard the prompt now mandates: an absence check over `hits` is
    unsound when `truncated` is true (the entity may sit in the 9186 rows not returned).
    The judge can only apply that rule if these columns are queryable — so pin them."""
    assert _rows(_ELASTIC, "SELECT total, returned, truncated FROM data") == [
        {"total": 9189, "returned": 3, "truncated": True},
    ]
    # and the absence check itself returns 0 — which, WITH truncated=true, is not absence
    assert _rows(_ELASTIC, "SELECT count(*) AS n FROM (SELECT unnest(hits) h FROM data) WHERE h.user = 'mallory'") \
        == [{"n": 0}]


def test_the_dead_recipe_stays_dead():
    """`unnest(result.hits)` — the idiom `sql.py` and `cli-adapter.md` used to document —
    errors, because no adapter emits a `result` wrapper. Pinning the failure keeps anyone
    from reintroducing the recipe on the strength of the old docs."""
    proc = _sql(_ELASTIC, "SELECT count(*) FROM (SELECT unnest(result.hits) h FROM data)")
    assert proc.returncode == 1  # EXIT_QUERY_ERROR: DuckDB rejected the SQL
    # the error must be ABOUT the missing `result` wrapper, not some unrelated failure
    assert "Binder Error" in proc.stderr
    assert 'Referenced table "result" not found' in proc.stderr


# Every authored surface that could re-teach the dead recipe. `test_judge_prompts_*`
# below covers only the two prompts; the recipe originally survived precisely because
# it was copied across several docs, so guard all of them at once.
_IDIOM_SURFACES = (
    _DEFENDER / "scripts" / "gather_tools" / "sql.py",
    _DEFENDER / "skills" / "connect" / "cli-adapter.md",
    _JUDGE / "compare.py",
    _JUDGE / "run.py",
    _JUDGE / "malicious.md",
    _JUDGE / "benign.md",
)


@pytest.mark.parametrize("surface", _IDIOM_SURFACES, ids=lambda p: p.name)
def test_no_surface_resurrects_the_result_envelope(surface):
    """`unnest(result.hits)` has no legitimate home anywhere: no adapter emits a `result`
    wrapper. sql.py's argparse EPILOG kept teaching it long after the module docstring
    stopped — and `defender-sql --help` is inside the judge's bash lane, so the fiction
    was one `--help` away from being copied back into a query."""
    assert "result.hits" not in surface.read_text(), f"{surface.name} re-teaches the dead recipe"


def test_esql_shape_on_the_real_tracked_payload():
    """`{columns,row_count,values}` (31/640) — driven off the real checked-in payload, not
    a hand-written one, so a change to the ES|QL adapter's output shape breaks this."""
    payload = _REAL_ESQL.read_text()
    doc = json.loads(payload)
    assert set(doc) >= {"columns", "row_count", "values"}, "the real fixture changed shape"
    assert _rows(payload, "SELECT row_count FROM data") == [{"row_count": doc["row_count"]}]
    assert _rows(payload, "SELECT count(*) AS n FROM (SELECT unnest(values) v FROM data)") \
        == [{"n": len(doc["values"])}]


def test_esql_values_are_positional_json_not_a_struct():
    """The trap the prompts must not fall into: `unnest(values)` yields a POSITIONAL
    `JSON[]`, NOT the named struct `unnest(hits)` yields. `v.<field>` — the idiom the
    prompt teaches for search hits — is a Binder Error here, so the ES|QL row of the
    shape table must teach positional indexing + a JSON unwrap instead."""
    payload = _REAL_ESQL.read_text()
    doc = json.loads(payload)
    field = doc["columns"][1]["name"]                       # a real ES|QL column name

    struct_idiom = _sql(payload, f"SELECT count(*) FROM (SELECT unnest(values) v FROM data) WHERE v.\"{field}\" = 'x'")
    assert struct_idiom.returncode == 1
    assert "not a struct" in struct_idiom.stderr

    # what the prompt now teaches: 1-based positional index + `->>'$'` to unwrap the JSON
    wanted = json.loads(json.dumps(doc["values"][0][1]))    # the real value at position 2
    assert _rows(payload, f"SELECT count(*) AS n FROM (SELECT unnest(values) v FROM data) WHERE v[2]->>'$' = '{wanted}'") \
        == [{"n": 1}]


def _payload_without_truncated(shape: str) -> str:
    """One payload per corpus shape that has no `truncated` column — ES|QL off the real
    tracked fixture, the other two hand-written (they are shape, not content)."""
    return {
        "esql": lambda: _REAL_ESQL.read_text(),
        "flat": lambda: json.dumps({"host": "web-1", "owner": "team.platform"}),
        "bare_array": lambda: json.dumps([{"user": "alice"}]),
    }[shape]()


@pytest.mark.parametrize("shape", ["esql", "flat", "bare_array"])
def test_truncation_probe_is_shape_specific_not_universal(shape):
    """`SELECT total, returned, truncated FROM data` is a Binder Error on every shape but
    search-hits — and ES|QL (31/640) plus flat objects (~230/640) are ~40% of the corpus.
    So the prompts must NOT mandate it as the unconditional first step; they must send the
    judge through `DESCRIBE data` (which runs on every shape) and gate the probe on
    `truncated` actually being a column."""
    payload = _payload_without_truncated(shape)
    proc = _sql(payload, "SELECT total, returned, truncated FROM data")
    assert proc.returncode == 1
    assert "Binder Error" in proc.stderr
    # DESCRIBE, by contrast, answers on every shape — which is why it goes first
    assert _rows(payload, "DESCRIBE data")


@pytest.mark.parametrize("prompt", ["malicious.md", "benign.md"])
def test_prompts_do_not_mandate_the_truncation_probe_unconditionally(prompt):
    """The regression guard for the above: `DESCRIBE data` must be taught, and the
    `total, returned, truncated` probe must never be introduced as the unconditional
    "run this first" step."""
    text = (_JUDGE / prompt).read_text()
    assert "DESCRIBE data" in text
    assert "SELECT total, returned, truncated FROM data` first" not in text


def test_flat_object_is_one_row():
    """A cmdb/identity lookup (~230/640) is a flat object -> one row, columns = its keys."""
    payload = json.dumps({"host": "web-1", "owner": "team.platform", "criticality": "high"})
    assert _rows(payload, "SELECT owner FROM data") == [{"owner": "team.platform"}]


def test_bare_array_is_one_row_per_element():
    """A bare array of docs (12/640) -> one row per element; no unnest needed."""
    payload = json.dumps([{"user": "alice"}, {"user": "bob"}, {"user": "alice"}])
    assert _rows(payload, "SELECT count(*) AS n FROM data WHERE user = 'alice'") == [{"n": 2}]


# ---------------------------------------------------------------------------
# reactive, payload-grounded guidance: the tool holds the payload the caller does
# not, so the shape/idiom/truncation advice is emitted on the actual failure rather
# than pre-taught in the prompt for every shape at once.
# ---------------------------------------------------------------------------

def test_query_error_on_hits_shape_hint_points_at_the_struct():
    """A wrong field on the search-hits shape: the error carries the idiom fix, naming the
    real columns and how to read the struct's fields — the "learn the field names" step the
    prompt used to spell out for every call."""
    proc = _sql('{"total":9,"returned":2,"truncated":true,"hits":[{"user":"a"}]}',
                "SELECT count(*) FROM (SELECT unnest(hits) h FROM data) WHERE h.usr = 'x'")
    assert proc.returncode == 1
    assert "hint:" in proc.stderr
    assert "columns [total, returned, truncated, hits]" in proc.stderr
    assert "unnest(hits) h FROM data LIMIT 1" in proc.stderr  # how to see the field names


def test_query_error_on_esql_shape_hint_gives_the_positional_map():
    """The killer case a prompt cannot pre-teach: struct-style access on ES|QL `values`
    fails, and the hint names the EXACT position of each field FOR THIS payload — grounded
    in the real fixture, not a generic table."""
    payload = _REAL_ESQL.read_text()
    doc = json.loads(payload)
    proc = _sql(payload,
                "SELECT count(*) FROM (SELECT unnest(values) v FROM data) WHERE v.\"source.ip\" = 'x'")
    assert proc.returncode == 1
    assert "POSITIONAL JSON array" in proc.stderr
    # the real column order, 1-based, is in the hint
    for i, col in enumerate(doc["columns"]):
        assert f"{i + 1}={col['name']}" in proc.stderr


def test_query_error_on_flat_shape_hint_names_the_columns():
    proc = _sql('{"host":"web-1","owner":"team.platform"}', "SELECT nope FROM data")
    assert proc.returncode == 1
    assert "columns [host, owner]" in proc.stderr
    assert "SELECT * FROM data" in proc.stderr


def test_truncated_payload_warns_on_a_SUCCESSFUL_query():
    """The truncation trap moved from the prompt to the tool: a successful query over a
    truncated payload carries a stderr note (the tool sees `truncated`, the caller may
    miss it), so a 0 is not silently read as absence."""
    proc = _sql('{"total":9,"returned":1,"truncated":true,"hits":[{"user":"a"}]}',
                "SELECT count(*) AS n FROM (SELECT unnest(hits) h FROM data) WHERE h.user = 'mallory'")
    assert proc.returncode == 0
    assert json.loads(proc.stdout) == [{"n": 0}]     # the query still succeeds
    assert "TRUNCATED" in proc.stderr
    assert "cannot support an absence refutation" in proc.stderr


def test_non_truncated_payload_emits_no_note():
    """The note fires ONLY on `truncated=true`; every other payload is silent, so the
    signal stays meaningful."""
    proc = _sql('{"total":2,"returned":2,"truncated":false,"hits":[{"user":"a"}]}',
                "SELECT count(*) AS n FROM data")
    assert proc.returncode == 0
    assert proc.stderr.strip() == ""


# ---------------------------------------------------------------------------
# the two NON-JSON shapes: loud failure, never a silent "absent"
# ---------------------------------------------------------------------------

def test_empty_payload_is_an_error_not_an_empty_result():
    """41/640 payloads are EMPTY files. `jq` exited 0 and printed nothing — which a refute
    primitive reads as "the projected entity is absent". `defender-sql` exits 2 with a
    message, so the judge is told the lead produced no observation at all."""
    proc = _sql("", "SELECT count(*) FROM data")
    assert proc.returncode == 2
    assert "no input on stdin" in proc.stderr
    # the message must SAY so — the judge reads this stderr and must not treat it as "0 rows"
    assert "NOT an empty result set" in proc.stderr


def test_markdown_payload_is_an_input_error():
    """25/640 payloads are the adapter's rendered text, not JSON. `jq` fails on these today
    too; `defender-sql` must fail loudly rather than yield a spurious empty table."""
    proc = _sql("## Query Results\n\n- **Matching events:** 197\n", "SELECT count(*) FROM data")
    assert proc.returncode == 2
    assert "not valid JSON" in proc.stderr


# ---------------------------------------------------------------------------
# drift guard: the prompts must teach an idiom that runs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("prompt", ["malicious.md", "benign.md"])
def test_judge_prompts_teach_a_live_idiom(prompt):
    """The prompts must name `defender-sql` + `unnest(hits)` and must NOT resurrect
    `unnest(result.hits)` or tell the judge to reach for `jq` (which it no longer has)."""
    text = (_JUDGE / prompt).read_text()
    assert "defender-sql" in text
    assert "unnest(hits)" in text
    assert "unnest(result.hits)" not in text
    assert "jq" not in text
    assert "truncated" in text  # the absence-check guard


# Every `cat … | defender-sql "…"` the prompts show, from fenced blocks and inline
# backticks alike. Deliberately matches ANY operand, absolute or relative — a regex that
# only found the absolute form would pass vacuously on exactly the bug it must catch.
_PROMPT_CMD_RE = re.compile(r"cat \S+ \| defender-sql \"[^\"]*\"")


@pytest.mark.parametrize("prompt", ["malicious.md", "benign.md"])
def test_every_command_the_prompt_teaches_passes_the_judges_own_gate(prompt):
    """The whole point of #569's "the documented recipe was dead" finding, turned into a
    gate. A worked example the judge copies must be one `decide_bash` would ALLOW — so a
    relative operand (resolves outside the read roots) or a `\\`-continuation (the parser
    splits on newlines before tokenizing) can never ship in a prompt again."""
    pytest.importorskip("pydantic_ai")
    from defender.runtime import permission
    from defender.learning.pipeline.judge.engine_pydantic import JUDGE_DEF
    from defender.runtime.agent_definition import RunScope, compile_policy_for

    # Through the REAL seam (#575): the judge's policy is compiled from its own def, and the
    # prompts' `/abs/path` payloads reach it the way production's do — as a `read_roots` entry
    # (gather_raw lives under the INVESTIGATION run dir, never the judge's own). The adversarial
    # leg (no ticket_cli) is the tighter of the two, so a command it allows both legs allow.
    root = Path("/abs/path")
    policy = compile_policy_for(
        JUDGE_DEF, Path("/run"), scope=RunScope(add_dirs=(root,)), defender_dir=_DEFENDER,
    )
    commands = _PROMPT_CMD_RE.findall((_JUDGE / prompt).read_text())
    assert commands, "the prompt shows no defender-sql command — did the example shape change?"
    for cmd in commands:
        decision = permission.decide_bash(
            cmd, policy=policy, run_dir=Path("/run"), defender_dir=_DEFENDER,
        )
        assert decision.allow, f"the prompt teaches a command its own gate denies: {cmd}"
