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
