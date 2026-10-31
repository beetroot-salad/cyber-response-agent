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
  order of STATS ... BY). Events are fingerprinted COUNT + SUM(_version); alerts may be
  fingerprinted COUNT only (C25 is unprobed), so the fake answers per FROM pattern and shapes the
  columns by what the query asks for: COUNT only -> [count, _index, hour]; COUNT + SUM -> [count,
  sum, _index, hour]. Expected alert values therefore accept either `[count, sum]` or `[count]`
  (keys are `<index>|<hour>` either way); event values are always `[count, sum]`.
  The fingerprint covers exactly the window `[window[0], as_of]` (D1: older history is served by
  Elasticsearch but not guaranteed, so it must not appear). ES|QL returns at most 1000 rows by
  default, so either one request with a LIMIT large enough or several (paged) requests whose union
  covers the window. The fake supports both: it cuts rows to the query's LIMIT and to the time
  range named by the query's own ISO-seconds timestamps (`YYYY-MM-DDTHH:MM:SS`; the first and
  last found are the bounds; a query naming fewer than two is unbounded), so time-chunked pages
  must spell their bounds in the query, not elsewhere. The hour truncation may sit after BY or in
  an EVAL whose alias is a BY key. A reply that looks truncated (row count == the request's LIMIT,
  or 1000 when it has none) is refused with an exception (r6.1), never accepted.
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


def _hours(start, count):
    return [(start + timedelta(hours=h)).strftime("%Y-%m-%dT%H:00:00.000Z") for h in range(count)]


def _dataset(indexes=3):
    """Every events index x hour bucket of the 31-day window (745 hours): far more than 1000 rows."""
    return [[10, 10, f"evt-lab-system.auth-{i}", hr] for i in range(indexes)
            for hr in _hours(datetime(2026, 9, 19, 8, tzinfo=UTC), 745)]


def _alert_dataset():
    """Alert-index rows over the same window, as [count, sum, _index, hour] (sum != count)."""
    return [[4, 9, "alr-lab-system", hr] for hr in _hours(datetime(2026, 9, 19, 8, tzinfo=UTC), 745)]


def _before_window():
    """Rows older than window[0] (D1: served, not guaranteed): the hour before and weeks earlier."""
    old = _hours(datetime(2026, 9, 19, 7, tzinfo=UTC), 1) + _hours(datetime(2026, 8, 30, tzinfo=UTC), 48)
    return ([[3, 3, f"evt-lab-system.auth-{i}", hr] for i in range(3) for hr in old],
            [[2, 5, "alr-lab-system", hr] for hr in old])


def _asks_sum(query):
    return "SUM(_VERSION)" in re.sub(r"\s+", "", query.upper())


def _check_fingerprint(got, events, alerts):
    """Keys are exactly the expected buckets; events [count, sum]; alerts [count, sum] or [count]."""
    key = lambda r: f"{r[2]}|{r[3][:13]}"  # noqa: E731
    assert set(got) == {key(r) for r in events + alerts}
    for r in events:
        assert got[key(r)] == [r[0], r[1]], key(r)
    for r in alerts:
        assert got[key(r)] in ([r[0], r[1]], [r[0]]), key(r)


class Docker:
    """Records every command and answers each `_query` with a canned ES|QL result.

    Rows are answered per FROM pattern: an events query gets `values`/`serve_rows` (each
    [count, sum, _index, hour]), an alerts query gets `alert_rows` (same shape) cut to the columns
    the query asks for (no SUM(_version) -> [count, _index, hour]); a query naming neither gets
    `values` as is (es_now). `values` rows are served in full. `serve_rows` models Elasticsearch:
    rows inside the time range named by the query's own timestamps (all rows if it names fewer than
    two; also applied to `alert_rows`), cut to the query's LIMIT (default 1000). `endless` answers
    every query with exactly LIMIT rows.
    """

    def __init__(self, values=None, serve_rows=None, alert_rows=None, endless=False):
        self.values, self.serve_rows, self.endless, self.calls = values, serve_rows, endless, []
        self.alert_rows = alert_rows or []

    def _rows(self, query):
        wide = _asks_sum(query)
        shape = (lambda r: r) if wide else (lambda r: [r[0], *r[2:]])
        if self.endless:
            return [shape([1, 1, f"idx-{i}", f"2026-09-{1 + i // 24 % 28:02d}T{i % 24:02d}:00:00.000Z"])
                    for i in range(_limit(query))]
        events = self.serve_rows if self.serve_rows is not None else self.values
        rows = []
        if EVENTS in query or ALERTS not in query:
            rows += events
        if ALERTS in query:
            rows += [shape(r) for r in self.alert_rows]
        if self.serve_rows is not None:
            stamps = sorted(re.findall(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d", query))
            if len(stamps) >= 2:
                rows = [r for r in rows if stamps[0] <= r[-1][:19] <= stamps[-1]]
        return rows[:_limit(query)]

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw))
        body = json.loads(argv[argv.index("-d") + 1]) if "-d" in argv else json.loads(kw["input"])
        rows = self._rows(body["query"])
        reply = {"columns": [{"name": f"c{i}", "type": "keyword"} for i in range(len(rows[0]))] if rows
                 else [], "values": rows}

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
        assert "COUNT(*)" in squeezed and re.search(r"METADATA [^|]*\b_INDEX\b", upper)
        assert "logs-*" not in query
        head, by = upper.split(" BY ", 1)
        assert "_INDEX" in by
        trunc = r"(?:DATE_TRUNC\(\s*1\s*HOURS?\s*,|BUCKET\([^,()]+,\s*1\s*HOURS?\s*\))"
        aliases = re.findall(rf"(\w+)\s*=\s*{trunc}", head)  # EVAL h = DATE_TRUNC(...) ... BY h
        assert re.search(trunc, by) or any(re.search(rf"\b{a}\b", by) for a in aliases), by
        if EVENTS in query:
            assert "SUM(_VERSION)" in squeezed and "_VERSION" in upper.split("METADATA", 1)[1]
            # alerts may be COUNT only: C25 is unprobed


@pytest.mark.parametrize(("as_of", "arrived_by"), [
    (AS_OF, ARRIVED_BY), ("2026-03-02T01:00:00Z", "2026-03-02T01:05:00Z")])
def test_fingerprint_filter_is_the_shared_cut_clause(as_of, arrived_by):
    """P5/D12: every request `filter` equals cut_clause(as_of, arrived_by), whatever the moments."""
    from defender.integrations.elastic_adapter import cut_clause
    docker, _ = _fingerprint(as_of, arrived_by)
    want = cut_clause(instant(as_of), instant(arrived_by))
    assert all(body["filter"] == want for body in docker.requests())


def test_fingerprint_covers_the_whole_window_even_when_it_exceeds_one_default_page():
    """O1/D1: every in-window bucket (events and alerts) comes back whole, and none older than window[0]."""
    data, alerts = _dataset(), _alert_dataset()
    old_events, old_alerts = _before_window()
    docker = Docker(serve_rows=old_events + data, alert_rows=old_alerts + alerts)
    got = _ops(docker).fingerprint(WINDOW, AS_OF, ARRIVED_BY)
    _check_fingerprint(got, data, alerts)
    assert not [k for k in got if k.split("|")[1] < WINDOW[0][:13]]


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
    events = [[1200, 1250, INDEX, HOUR], [7, 7, INDEX, "2026-10-20T09:00:00.000Z"]]
    alerts = [[5, 9, "alr-lab-system", HOUR]]
    got = _ops(Docker(events, alert_rows=alerts)).fingerprint(WINDOW, AS_OF, ARRIVED_BY)
    _check_fingerprint(got, events, alerts)


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
