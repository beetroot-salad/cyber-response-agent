"""#1347 O1/O6/P5/D12 (FR1): the production lab ops, tested through a recorded `run=` seam.

Entry point bound by this contract: `playground-v2/scripts/lab_ops.py::LabOps(run=subprocess.run,
*, context="soc-playground", es_container="elasticsearch", events_pattern, alerts_pattern)`,
the class `capture_case.py` and `launch_frozen.py` use for Elasticsearch (both expose it as the
module attribute `LabOps`). Its methods are those the capture and launcher fakes stand in for:

* `fingerprint(window, as_of, arrived_by) -> {"<index>|<YYYY-MM-DDTHH>": [count, version_sum]}`
  sends one ES|QL `POST .../_query` inside the ES container with `docker --context <context>
  exec`; the JSON request body rides in argv after `-d` (or on stdin as `input=`). The reply is
  the ES|QL JSON result, `-w "\\n%{http_code}"` style (body, newline, status); result columns are
  read by position: count, version sum, `_index`, hour (pinned because ES|QL fixes the output
  order of STATS ... BY). The fingerprint must cover the whole window: ES|QL returns at most 1000
  rows by default, so either one request with a LIMIT large enough or several (paged) requests
  whose union covers it, and a reply that looks truncated (row count == the request's LIMIT, or
  1000 when it has none) is refused with an exception (r6.1), never accepted.
* `es_now() -> str` sends an ES|QL query to the same door and returns the instant in the first
  cell of the reply; it never reads the local clock.

The expected request filter is `defender.integrations.elastic_adapter.cut_clause(as_of,
arrived_by)`, the shared builder (P5/D12), imported here rather than re-spelled.
"""
from __future__ import annotations

import importlib.util
import json
import re
from datetime import datetime, timedelta, UTC
from pathlib import Path

import pytest
from _lab_fakes import ES_NOW, instant

SCRIPTS = Path(__file__).resolve().parents[1]
WINDOW = ["2026-09-19T08:00:00Z", "2026-10-20T09:00:00Z"]
AS_OF, ARRIVED_BY = "2026-10-20T09:00:00Z", "2026-10-20T09:03:17Z"
EVENTS, ALERTS = "evt-lab-*", "alr-lab-*"
INDEX, HOUR = "evt-lab-system.auth-2026.10.20", "2026-10-20T08:00:00.000Z"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"{name}_1347_ops", SCRIPTS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _limit(query: str) -> int:
    found = re.findall(r"\bLIMIT\s+(\d+)", query, flags=re.IGNORECASE)
    return int(found[-1]) if found else 1000  # ES|QL's default row cap


def _dataset(indexes=3):
    """Every index x hour bucket of the 31-day window (745 hours): far more than 1000 rows."""
    start = datetime(2026, 9, 19, 8, tzinfo=UTC)
    return [[10, 10, f"evt-lab-system.auth-{i}", (start + timedelta(hours=h)).strftime(
        "%Y-%m-%dT%H:00:00.000Z")] for i in range(indexes) for h in range(745)]


class Docker:
    """Records every command and answers each `_query` with a canned ES|QL result.

    `values` rows are served in full. `serve_rows` models Elasticsearch: rows inside the time
    range named by the query's own timestamps (all rows if it names fewer than two), cut to the
    query's LIMIT (default 1000). `endless` answers every query with exactly LIMIT rows.
    """

    def __init__(self, values=None, serve_rows=None, endless=False):
        self.values, self.serve_rows, self.endless, self.calls = values, serve_rows, endless, []

    def _rows(self, query):
        if self.endless:
            return [[1, 1, f"idx-{i}", f"2026-09-{1 + i // 24 % 28:02d}T{i % 24:02d}:00:00.000Z"]
                    for i in range(_limit(query))]
        if self.serve_rows is None:
            return self.values
        stamps = sorted(re.findall(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d", query))
        rows = self.serve_rows
        if len(stamps) >= 2:
            rows = [r for r in rows if stamps[0] <= r[3][:19] <= stamps[-1]]
        return rows[:_limit(query)]

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw))
        body = json.loads(argv[argv.index("-d") + 1]) if "-d" in argv else json.loads(kw["input"])
        reply = {"columns": [{"name": "a", "type": "long"}, {"name": "b", "type": "long"},
                             {"name": "c", "type": "keyword"}, {"name": "d", "type": "date"}],
                 "values": self._rows(body["query"])}

        class Done:
            returncode, stderr = 0, ""
            stdout = json.dumps(reply) + "\n200"
        return Done()

    def requests(self) -> list[dict]:
        bodies = []
        for argv, kw in self.calls:
            assert argv[:5] == ["docker", "--context", "soc-playground", "exec", argv[4]]
            assert "elasticsearch" in argv
            assert any(a.endswith("/_query") or "/_query?" in a for a in argv), argv
            bodies.append(json.loads(argv[argv.index("-d") + 1]) if "-d" in argv
                          else json.loads(kw["input"]))
        assert bodies, "no lab request was sent"
        return bodies

    def request(self) -> dict:
        assert len(self.calls) == 1, f"expected one lab request, saw {len(self.calls)}"
        return self.requests()[0]


def _ops(docker):
    return _load("lab_ops").LabOps(run=docker, context="soc-playground",
                                   es_container="elasticsearch",
                                   events_pattern=EVENTS, alerts_pattern=ALERTS)


def _fingerprint(as_of=AS_OF, arrived_by=ARRIVED_BY):
    docker = Docker([[1200, 1200, INDEX, HOUR]])
    return docker, _ops(docker).fingerprint(WINDOW, as_of, arrived_by)


def test_fingerprint_sends_the_per_index_hour_esql_over_the_configured_patterns():
    """O1/D1/C25: COUNT per index x hour (1 h buckets) over both patterns; SUM(_version) for events."""
    docker, _ = _fingerprint()
    queries = [re.sub(r"\s+", " ", b["query"]) for b in docker.requests()]
    assert any(EVENTS in q for q in queries) and any(ALERTS in q for q in queries)
    for query in queries:
        upper = re.sub(r"\s*,\s*", ", ", query.upper())
        squeezed = upper.replace(" ", "")
        assert "METADATA _INDEX, _VERSION" in upper and "COUNT(*)" in squeezed
        assert "logs-*" not in query
        by = upper.split(" BY ", 1)[1]
        assert "_INDEX" in by
        assert re.search(r"(DATE_TRUNC\(\s*1\s*HOURS?\s*,|BUCKET\([^,()]+,\s*1\s*HOURS?\s*\))", by), by
        if EVENTS in query:
            assert "SUM(_VERSION)" in squeezed  # alerts are not pinned: C25 is unprobed


@pytest.mark.parametrize(("as_of", "arrived_by"), [
    (AS_OF, ARRIVED_BY), ("2026-03-02T01:00:00Z", "2026-03-02T01:05:00Z")])
def test_fingerprint_filter_is_the_shared_cut_clause(as_of, arrived_by):
    """P5/D12: every request `filter` equals cut_clause(as_of, arrived_by), whatever the moments."""
    from defender.integrations.elastic_adapter import cut_clause
    docker, _ = _fingerprint(as_of, arrived_by)
    want = cut_clause(instant(as_of), instant(arrived_by))
    assert all(body["filter"] == want for body in docker.requests())


def test_fingerprint_covers_the_whole_window_even_when_it_exceeds_one_default_page():
    """O1/D1: 2235 index x hour buckets come back whole (one big LIMIT, or paged requests)."""
    data = _dataset()
    docker = Docker(serve_rows=data)
    got = _ops(docker).fingerprint(WINDOW, AS_OF, ARRIVED_BY)
    assert got == {f"{r[2]}|{r[3][:13]}": [r[0], r[1]] for r in data}


def test_fingerprint_refuses_a_reply_that_looks_truncated():
    """O1/r6.1: a reply with exactly as many rows as the request's LIMIT (1000 if none) raises."""
    ops = _ops(Docker(endless=True))
    try:
        ops.fingerprint(WINDOW, AS_OF, ARRIVED_BY)
    except (AttributeError, TypeError, NameError):
        raise  # an implementation bug is not a refusal
    except Exception:  # noqa: BLE001 - the refusal's type is the implementation's choice
        return
    pytest.fail("a reply with exactly LIMIT rows was accepted")


def test_fingerprint_answers_count_and_version_sum_keyed_by_index_and_hour():
    """Data model: the reply rows become {"<index>|<hour>": [count, sum]}."""
    docker = Docker([[1200, 1250, INDEX, HOUR], [7, 7, INDEX, "2026-10-20T09:00:00.000Z"]])
    got = _ops(docker).fingerprint(WINDOW, AS_OF, ARRIVED_BY)
    assert got == {f"{INDEX}|2026-10-20T08": [1200, 1250], f"{INDEX}|2026-10-20T09": [7, 7]}


def test_es_now_reads_the_elasticsearch_clock_not_the_local_one():
    """O1/D4: the returned instant is the one Elasticsearch answered, via the lab door."""
    docker = Docker([[ES_NOW]])
    got = _ops(docker).es_now()
    docker.request()
    assert instant(got) == instant(ES_NOW)


@pytest.mark.parametrize("script", ["capture_case", "launch_frozen"])
def test_capture_and_launcher_use_the_one_production_ops_class(script):
    """FR1: both lab scripts expose the same LabOps, so there is no second fingerprint."""
    assert _load(script).LabOps.__name__ == "LabOps"
    assert _load(script).LabOps.__module__.endswith("lab_ops")
