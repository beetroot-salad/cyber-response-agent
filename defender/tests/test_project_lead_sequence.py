"""Tests for the lead-sequence projector's query normalization.

Regression coverage for the ad-hoc-lead crash: gather writes ad-hoc
query sidecars as ``{id, system, body, measurement}`` with no ``params``
key, which used to KeyError in ``dump_yaml`` and abort the whole
projection (and with it the learning-loop handoff in run.py).
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "project_lead_sequence.py"
)
_spec = importlib.util.spec_from_file_location("project_lead_sequence", _MODULE_PATH)
pls = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pls)


def test_normalize_query_preserves_structured():
    q = {"id": "host-state.passwd", "params": {"host": "db-1"}}
    assert pls._normalize_query(q) is q


def test_normalize_query_folds_adhoc_fields_into_params():
    q = {
        "id": "ad-hoc",
        "system": "host-state",
        "body": "passwd db-1 | grep 1003",
        "measurement": "identify uid 1003 on db-1",
    }
    out = pls._normalize_query(q)
    assert out["id"] == "ad-hoc"
    assert out["params"] == {
        "system": "host-state",
        "body": "passwd db-1 | grep 1003",
        "measurement": "identify uid 1003 on db-1",
    }


def test_normalize_query_handles_id_only():
    assert pls._normalize_query({"id": "host-state.unknown"}) == {
        "id": "host-state.unknown",
        "params": {},
    }


def _write_jsonl(path, rows):
    path.write_text("".join(__import__("json").dumps(r) + "\n" for r in rows))


def test_materialize_single_query_from_executed_log(tmp_path):
    run = tmp_path / "run"
    (run / "gather_raw" / "0").mkdir(parents=True)
    (run / "gather_raw" / "0" / "0.json").write_text('{"name":"web-1"}')
    _write_jsonl(run / "executed_queries.jsonl", [
        {"lead": "0", "seq": 0, "system": "stub-cmdb", "verb": "host-lookup",
         "query_id": "stub-cmdb.host-lookup", "params": {"arg0": "web-1"},
         "payload_path": "gather_raw/0/0.json", "payload_status": "ok",
         "payload_digest": "16 bytes, 1 line(s)"},
    ])
    pls.materialize_from_executed_queries(run)

    import json
    assert (run / "gather_raw" / "0.json").read_text() == '{"name":"web-1"}'
    obs = json.loads((run / "gather_raw" / "0.observations.json").read_text())
    assert obs["queries"][0]["id"] == "stub-cmdb.host-lookup"   # faithful id
    assert obs["queries"][0]["params"] == {"arg0": "web-1"}
    assert obs["payload_status"] == "ok"


def test_materialize_multi_query_suffixes_canonical_paths(tmp_path):
    run = tmp_path / "run"
    (run / "gather_raw" / "1").mkdir(parents=True)
    (run / "gather_raw" / "1" / "0.json").write_text("proc")
    (run / "gather_raw" / "1" / "1.json").write_text("passwd")
    _write_jsonl(run / "executed_queries.jsonl", [
        {"lead": "1", "seq": 0, "system": "host-query", "verb": "proc-tree",
         "query_id": "host-query.proc-tree", "params": {"arg0": "db-1"},
         "payload_path": "gather_raw/1/0.json", "payload_status": "ok", "payload_digest": "x"},
        {"lead": "1", "seq": 1, "system": "host-query", "verb": "passwd",
         "query_id": "host-query.passwd", "params": {"arg0": "db-1"},
         "payload_path": "gather_raw/1/1.json", "payload_status": "ok", "payload_digest": "x"},
    ])
    pls.materialize_from_executed_queries(run)

    import json
    assert (run / "gather_raw" / "1a.json").read_text() == "proc"
    assert (run / "gather_raw" / "1b.json").read_text() == "passwd"
    assert json.loads((run / "gather_raw" / "1a.observations.json").read_text())["queries"][0]["id"] == "host-query.proc-tree"
    assert json.loads((run / "gather_raw" / "1b.observations.json").read_text())["queries"][0]["id"] == "host-query.passwd"
    # the multi-query sidecars are exactly what load_queries_from_observations globs
    qs = pls.load_queries_from_observations(run, 1)
    assert {q["id"] for q in qs} == {"host-query.proc-tree", "host-query.passwd"}


def test_materialize_noop_without_log(tmp_path):
    run = tmp_path / "run"
    (run / "gather_raw").mkdir(parents=True)
    pls.materialize_from_executed_queries(run)  # must not raise
    assert not list((run / "gather_raw").glob("*.observations.json"))


def test_dump_yaml_renders_adhoc_lead_without_crashing():
    doc = {
        "case_id": "case-1",
        "alert_ref": "alert.json",
        "entries": [
            {
                "position": 0,
                "lead_description": {"goal": "g", "what_to_summarize": []},
                "queries": [
                    pls._normalize_query(
                        {
                            "id": "ad-hoc",
                            "system": "host-state",
                            "body": "passwd db-1 | grep 1003",
                            "measurement": "identify uid 1003",
                        }
                    )
                ],
                "result_ref": "gather_raw/0.json",
            }
        ],
    }
    text = pls.dump_yaml(doc)
    assert "id: ad-hoc" in text
    assert "body:" in text
    assert "measurement:" in text
