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
    assert proc.returncode != 0
    assert "result" in proc.stderr


def test_esql_shape_on_the_real_tracked_payload():
    """`{columns,row_count,values}` (31/640) — driven off the real checked-in payload, not
    a hand-written one, so a change to the ES|QL adapter's output shape breaks this."""
    payload = _REAL_ESQL.read_text()
    doc = json.loads(payload)
    assert set(doc) >= {"columns", "row_count", "values"}, "the real fixture changed shape"
    assert _rows(payload, "SELECT row_count FROM data") == [{"row_count": doc["row_count"]}]
    assert _rows(payload, "SELECT count(*) AS n FROM (SELECT unnest(values) v FROM data)") \
        == [{"n": len(doc["values"])}]


def test_flat_object_is_one_row():
    """A cmdb/identity lookup (~230/640) is a flat object -> one row, columns = its keys."""
    payload = json.dumps({"host": "web-1", "owner": "team.platform", "criticality": "high"})
    assert _rows(payload, "SELECT owner FROM data") == [{"owner": "team.platform"}]


def test_bare_array_is_one_row_per_element():
    """A bare array of docs (12/640) -> one row per element; no unnest needed."""
    payload = json.dumps([{"user": "alice"}, {"user": "bob"}, {"user": "alice"}])
    assert _rows(payload, "SELECT count(*) AS n FROM data WHERE user = 'alice'") == [{"n": 2}]


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
