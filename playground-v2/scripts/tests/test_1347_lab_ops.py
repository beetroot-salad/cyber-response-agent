"""#1347 O1/O6/P5/D12 (FR1): the production lab ops, tested through a recorded `run=` seam.

Entry point bound by this contract: `playground-v2/scripts/lab_ops.py::LabOps(run=subprocess.run,
*, context="soc-playground", es_container="elasticsearch", events_pattern, alerts_pattern)`,
the class `capture_case.py` and `launch_frozen.py` use for Elasticsearch (both expose it as the
module attribute `LabOps`). Its methods are those the capture and launcher fakes stand in for:

* `fingerprint(window, as_of, arrived_by) -> {"<index>|<YYYY-MM-DDTHH>": [count, version_sum]}`
  sends one ES|QL `POST .../_query` inside the ES container with `docker --context <context>
  exec`; the JSON request body rides in argv after `-d` (or on stdin as `input=`). The reply is
  the ES|QL JSON result, `-w "\\n%{http_code}"` style (body, newline, status); result columns are
  read by position: count, version sum, `_index`, hour (ES|QL's order for STATS ... BY).
* `es_now() -> str` sends an ES|QL query to the same door and returns the instant in the first
  cell of the reply; it never reads the local clock.

The expected request filter is `defender.integrations.elastic_adapter.cut_clause(as_of,
arrived_by)`, the shared builder (P5/D12), imported here rather than re-spelled.
"""
from __future__ import annotations

import importlib.util
import json
import re
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


class Docker:
    """Records every command and answers each `_query` with a canned ES|QL result."""

    def __init__(self, values):
        self.values, self.calls = values, []

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw))
        reply = {"columns": [{"name": "a", "type": "long"}, {"name": "b", "type": "long"},
                             {"name": "c", "type": "keyword"}, {"name": "d", "type": "date"}],
                 "values": self.values}

        class Done:
            returncode, stderr = 0, ""
            stdout = json.dumps(reply) + "\n200"
        return Done()

    def request(self) -> dict:
        assert len(self.calls) == 1, f"expected one lab request, saw {len(self.calls)}"
        argv, kw = self.calls[0]
        assert argv[:5] == ["docker", "--context", "soc-playground", "exec", argv[4]]
        assert "elasticsearch" in argv
        assert any(a.endswith("/_query") or "/_query?" in a for a in argv), argv
        if "-d" in argv:
            return json.loads(argv[argv.index("-d") + 1])
        return json.loads(kw["input"])


def _ops(docker):
    return _load("lab_ops").LabOps(run=docker, context="soc-playground",
                                   es_container="elasticsearch",
                                   events_pattern=EVENTS, alerts_pattern=ALERTS)


def _fingerprint(as_of=AS_OF, arrived_by=ARRIVED_BY):
    docker = Docker([[1200, 1200, INDEX, HOUR]])
    return docker, _ops(docker).fingerprint(WINDOW, as_of, arrived_by)


def test_fingerprint_sends_the_per_index_hour_esql_over_the_configured_patterns():
    """O1/D1: METADATA _index, _version; COUNT(*) and SUM(_version) per index x hour; both patterns."""
    docker, _ = _fingerprint()
    query = re.sub(r"\s+", " ", docker.request()["query"])
    upper = re.sub(r"\s*,\s*", ", ", query.upper())
    assert "METADATA _INDEX, _VERSION" in upper
    assert "COUNT(*)" in upper.replace(" ", "") and "SUM(_VERSION)" in upper.replace(" ", "")
    assert EVENTS in query and ALERTS in query
    assert "logs-*" not in query
    by = upper.split(" BY ", 1)[1]
    assert "_INDEX" in by and ("DATE_TRUNC" in by or "BUCKET" in by)
    assert "2026-09-19T08:00:00" in query and "2026-10-20T09:00:00" in query


@pytest.mark.parametrize(("as_of", "arrived_by"), [
    (AS_OF, ARRIVED_BY), ("2026-03-02T01:00:00Z", "2026-03-02T01:05:00Z")])
def test_fingerprint_filter_is_the_shared_cut_clause(as_of, arrived_by):
    """P5/D12: the request `filter` equals cut_clause(as_of, arrived_by), whatever the moments."""
    from defender.integrations.elastic_adapter import cut_clause
    docker, _ = _fingerprint(as_of, arrived_by)
    assert docker.request()["filter"] == cut_clause(as_of, arrived_by)


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
