"""Tests for the two-table read/join surface (`learning/lead_repository.py`).

Exercises the readers, the join, the actor-view integrity boundary, the
render helpers, the narration cross-check, and missing/malformed-artifact
tolerance. Fixtures write the two *live* tables directly:

  gather_raw/{lead_id}.lead.json   — leads table (goal, what_to_summarize)
  executed_queries.jsonl           — queries table (FK lead_id, by-ref payload)
  gather_raw/{lead_id}/{seq}.json   — payloads
"""
from __future__ import annotations

import json
from pathlib import Path

from defender.learning import lead_repository as lr


def _lead(run: Path, lead_id: str, goal: str, wts: list[str]) -> None:
    gd = run / "gather_raw"
    gd.mkdir(parents=True, exist_ok=True)
    (gd / f"{lead_id}.lead.json").write_text(
        json.dumps({"goal": goal, "what_to_summarize": wts})
    )


def _query(
    run: Path,
    lead_id: str,
    seq: int,
    *,
    query_id: str = "stub-cmdb.host-lookup",
    params: dict | None = None,
    payload: str | None = "{}",
    status: str = "ok",
) -> None:
    """Write one payload + append one queries-table row."""
    run.mkdir(parents=True, exist_ok=True)
    rel = None
    if payload is not None:
        ld = run / "gather_raw" / lead_id
        ld.mkdir(parents=True, exist_ok=True)
        (ld / f"{seq}.json").write_text(payload)
        rel = f"gather_raw/{lead_id}/{seq}.json"
    rec = {
        "lead_id": lead_id,
        "seq": seq,
        "system": "stub-cmdb",
        "verb": query_id.split(".", 1)[-1],
        "query_id": query_id,
        "params": params or {"arg0": "web-1"},
        "raw_command": "python3 cmdb_cli.py host-lookup web-1",
        "payload_path": rel,
        "exit_code": 0 if status != "error" else 1,
        "payload_status": status,
        "payload_digest": "2 bytes, 1 line(s)",
    }
    with (run / "executed_queries.jsonl").open("a") as fh:
        fh.write(json.dumps(rec) + "\n")


def _summary(
    run: Path,
    lead_id: str,
    payload_seq: int | None,
    summary_seq: int,
    *,
    label: str = "distinct-users",
    snippet: str | None = None,
    output: str = "3",
    output_status: str = "ok",
) -> None:
    """Append one row to summaries.jsonl, matching record_summary's schema.

    `tools` defaults to `["jq"]` and `exit_code` is derived from `output_status`
    (the wrapper's invariant); a test needing other values writes the row raw.
    The default `snippet` reads *this row's own* `(lead_id, payload_seq)` payload
    so the recorded code stays consistent with the FK it is filed under.
    """
    run.mkdir(parents=True, exist_ok=True)
    if snippet is None:
        seq = payload_seq if isinstance(payload_seq, int) else 0
        snippet = (
            f"jq '[.[].data.srcuser] | unique | length' gather_raw/{lead_id}/{seq}.json"
        )
    rec = {
        "lead_id": lead_id,
        "payload_seq": payload_seq,
        "summary_seq": summary_seq,
        "label": label,
        "tools": ["jq"],
        "snippet": snippet,
        "output": output,
        "exit_code": 0 if output_status == "ok" else 1,
        "output_status": output_status,
    }
    with (run / "summaries.jsonl").open("a") as fh:
        fh.write(json.dumps(rec) + "\n")


# --------------------------------------------------------------------------
# load_leads
# --------------------------------------------------------------------------


def test_load_leads_keys_on_lead_id(tmp_path):
    run = tmp_path / "run"
    _lead(run, "l-001", "Trace the FIM write", ["apt history"])
    _lead(run, "l-002", "Check auth", [])
    leads = lr.load_leads(run)
    assert set(leads) == {"l-001", "l-002"}
    assert leads["l-001"] == {"goal": "Trace the FIM write", "what_to_summarize": ["apt history"]}


def test_load_leads_missing_dir_returns_empty(tmp_path):
    assert lr.load_leads(tmp_path / "nope") == {}


def test_load_leads_skips_payload_subdirs_and_malformed(tmp_path):
    run = tmp_path / "run"
    _lead(run, "l-001", "g", [])
    _query(run, "l-001", 0)  # creates gather_raw/l-001/0.json — must be ignored
    (run / "gather_raw" / "bad.lead.json").write_text("{not json")
    leads = lr.load_leads(run)
    assert set(leads) == {"l-001"}


def test_load_leads_defaults_missing_goal_and_bad_wts(tmp_path):
    run = tmp_path / "run"
    (run / "gather_raw").mkdir(parents=True)
    (run / "gather_raw" / "l-001.lead.json").write_text(json.dumps({"what_to_summarize": "x"}))
    leads = lr.load_leads(run)
    assert leads["l-001"] == {"goal": "", "what_to_summarize": []}


# --------------------------------------------------------------------------
# load_queries
# --------------------------------------------------------------------------


def test_load_queries_order_and_raw_ref(tmp_path):
    run = tmp_path / "run"
    _query(run, "l-001", 0)
    _query(run, "l-001", 1)
    rows = lr.load_queries(run)
    assert [r.seq for r in rows] == [0, 1]
    assert rows[0].lead_id == "l-001"
    assert rows[0].raw_ref == run / "gather_raw/l-001/0.json"
    assert rows[0].raw_ref.read_text() == "{}"


def test_load_queries_missing_log_returns_empty(tmp_path):
    assert lr.load_queries(tmp_path / "run") == []


def test_load_queries_raw_ref_none_on_failed_write(tmp_path):
    run = tmp_path / "run"
    _query(run, "l-001", 0, payload=None)  # payload_path: null
    rows = lr.load_queries(run)
    assert rows[0].raw_ref is None


def test_load_queries_skips_blank_and_non_json_and_no_lead(tmp_path):
    run = tmp_path / "run"
    _query(run, "l-001", 0)
    with (run / "executed_queries.jsonl").open("a") as fh:
        fh.write("\n")
        fh.write("not json\n")
        fh.write(json.dumps({"seq": 9, "query_id": "x"}) + "\n")  # no lead_id
    rows = lr.load_queries(run)
    assert [r.lead_id for r in rows] == ["l-001"]


# --------------------------------------------------------------------------
# joined
# --------------------------------------------------------------------------


def test_joined_nests_queries_on_fk(tmp_path):
    run = tmp_path / "run"
    _lead(run, "l-001", "g1", ["d1"])
    _query(run, "l-001", 0)
    _query(run, "l-001", 1)
    jl = lr.joined(run)
    assert len(jl) == 1
    assert jl[0].lead_id == "l-001"
    assert jl[0].goal == "g1"
    assert [q.seq for q in jl[0].queries] == [0, 1]
    assert jl[0].orphan is False


def test_joined_lead_with_no_queries_is_kept(tmp_path):
    run = tmp_path / "run"
    _lead(run, "l-001", "g", [])
    jl = lr.joined(run)
    assert len(jl) == 1
    assert jl[0].queries == []
    assert jl[0].orphan is False


def test_joined_query_with_no_lead_is_orphan(tmp_path):
    run = tmp_path / "run"
    _query(run, "l-009", 0)  # no sidecar for l-009
    jl = lr.joined(run)
    assert len(jl) == 1
    assert jl[0].lead_id == "l-009"
    assert jl[0].orphan is True
    assert jl[0].goal is None


def test_joined_orders_ran_before_queryless_and_orphans_last(tmp_path):
    run = tmp_path / "run"
    _lead(run, "l-001", "ran", [])
    _lead(run, "l-002", "queryless", [])
    _query(run, "l-001", 0)
    _query(run, "l-009", 1)  # orphan
    order = [j.lead_id for j in lr.joined(run)]
    assert order == ["l-001", "l-002", "l-009"]


# --------------------------------------------------------------------------
# actor_view — the integrity boundary
# --------------------------------------------------------------------------


def test_actor_view_only_queries(tmp_path):
    run = tmp_path / "run"
    _lead(run, "l-001", "SECRET GOAL", ["secret dim"])
    _query(run, "l-001", 0, params={"arg0": "web-1"})
    view = lr.actor_view(run)
    assert view["case_id"] == "run"
    assert view["leads"] == [
        {"lead_id": "l-001", "queries": [{"query_id": "stub-cmdb.host-lookup", "params": {"arg0": "web-1"}}]}
    ]


def test_actor_view_never_reads_leads_table(tmp_path):
    """The redaction is a column-set boundary: actor_view must work — and
    leak nothing — even with the leads table entirely absent."""
    run = tmp_path / "run"
    _lead(run, "l-001", "SECRET", ["x"])
    _query(run, "l-001", 0)
    # Delete the leads table; actor_view must still produce the query view.
    (run / "gather_raw" / "l-001.lead.json").unlink()
    rendered = lr.render_actor_view_yaml(run)
    assert "SECRET" not in rendered
    assert "l-001" in rendered
    view = lr.actor_view(run)
    assert view["leads"][0]["lead_id"] == "l-001"


def test_actor_view_omits_queryless_lead(tmp_path):
    run = tmp_path / "run"
    _lead(run, "l-001", "g", [])  # dispatched but ran nothing
    view = lr.actor_view(run)
    assert view["leads"] == []


# --------------------------------------------------------------------------
# render helpers
# --------------------------------------------------------------------------


def test_render_joined_yaml_carries_goal_and_status(tmp_path):
    import yaml

    run = tmp_path / "run"
    _lead(run, "l-001", "the goal", ["dim"])
    _query(run, "l-001", 0, status="ok")
    doc = yaml.safe_load(lr.render_joined_yaml(run))
    lead = doc["leads"][0]
    assert lead["goal"] == "the goal"
    assert lead["what_to_summarize"] == ["dim"]
    assert lead["queries"][0]["payload_status"] == "ok"


# --------------------------------------------------------------------------
# narration cross-check
# --------------------------------------------------------------------------


def test_narration_crosscheck_clean(tmp_path):
    run = tmp_path / "run"
    _lead(run, "l-001", "g", [])
    _query(run, "l-001", 0)
    report = lr.narration_crosscheck(run, {"l-001"})
    assert report["ok"] is True
    assert report["missing_from_narration"] == []
    assert report["queries_without_lead"] == []


def test_narration_crosscheck_missing_from_narration(tmp_path):
    run = tmp_path / "run"
    _lead(run, "l-002", "g", [])  # dispatched but not a :L row
    _query(run, "l-002", 0)
    report = lr.narration_crosscheck(run, {"l-001"})
    assert report["missing_from_narration"] == ["l-002"]
    assert report["ok"] is False


def test_narration_crosscheck_query_without_lead_warns(tmp_path):
    run = tmp_path / "run"
    _query(run, "l-009", 0)  # FK with no sidecar
    report = lr.narration_crosscheck(run, {"l-009"})
    assert report["queries_without_lead"] == ["l-009"]
    assert report["ok"] is False


def test_narration_crosscheck_lead_without_queries_is_monitor(tmp_path):
    run = tmp_path / "run"
    _lead(run, "l-001", "g", [])
    report = lr.narration_crosscheck(run, {"l-001"})
    assert report["leads_without_queries"] == ["l-001"]
    assert report["ok"] is True  # monitor, not a warn-class failure


def test_narration_crosscheck_from_run_parses_l_ids(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    _lead(run, "l-001", "g", [])
    _query(run, "l-001", 0)
    (run / "investigation.md").write_text(
        "## CONTEXTUALIZE\n\n"
        "```invlang\n"
        ":L findings [id|loop|name|target|tests|system|window]\n"
        "l-001|1|trace|v-001|h-001|stub-cmdb|±10m\n"
        "```\n"
    )
    report = lr.narration_crosscheck_from_run(run)
    assert report["missing_from_narration"] == []
    assert report["ok"] is True


# --------------------------------------------------------------------------
# Malformed-row tolerance (readers never raise) + absolute-path guard
# --------------------------------------------------------------------------


def _raw_row(run: Path, rec: dict) -> None:
    run.mkdir(parents=True, exist_ok=True)
    with (run / "executed_queries.jsonl").open("a") as fh:
        fh.write(json.dumps(rec) + "\n")


def test_load_queries_tolerates_null_and_non_numeric_seq_exit_code(tmp_path):
    run = tmp_path / "run"
    _raw_row(run, {"lead_id": "l-001", "seq": None, "exit_code": None, "query_id": "s.v"})
    _raw_row(run, {"lead_id": "l-002", "seq": "0a", "exit_code": "x", "query_id": "s.v"})
    rows = lr.load_queries(run)  # must not raise
    assert [r.lead_id for r in rows] == ["l-001", "l-002"]
    assert [r.seq for r in rows] == [0, 0]
    assert [r.exit_code for r in rows] == [0, 0]


def test_actor_view_tolerates_malformed_seq(tmp_path):
    run = tmp_path / "run"
    _raw_row(run, {"lead_id": "l-001", "seq": None, "query_id": "s.v", "params": {}})
    view = lr.actor_view(run)  # the integrity boundary must not raise either
    assert view["leads"][0]["lead_id"] == "l-001"


def test_load_queries_raw_ref_none_on_absolute_payload_path(tmp_path):
    run = tmp_path / "run"
    _raw_row(run, {"lead_id": "l-001", "seq": 0, "query_id": "s.v",
                   "payload_path": "/etc/passwd"})
    rows = lr.load_queries(run)
    assert rows[0].raw_ref is None  # absolute path must not escape the run dir


def test_joined_orders_ran_by_execution_not_alphabetical(tmp_path):
    """seq resets per-lead, so ran order must follow execution (first-seen in
    the queries log), not lead_id sort — matching actor_view."""
    run = tmp_path / "run"
    _lead(run, "l-005", "first", [])
    _lead(run, "l-001", "second", [])
    _query(run, "l-005", 0)   # executed first
    _query(run, "l-001", 0)   # executed second
    joined_order = [j.lead_id for j in lr.joined(run)]
    actor_order = [lead["lead_id"] for lead in lr.actor_view(run)["leads"]]
    assert joined_order == ["l-005", "l-001"]
    assert joined_order == actor_order


# --------------------------------------------------------------------------
# stage_tables
# --------------------------------------------------------------------------


def test_stage_tables_copies_both_tables(tmp_path):
    src = tmp_path / "src"
    _lead(src, "l-001", "g", [])
    _query(src, "l-001", 0)
    dst = tmp_path / "dst"
    lr.stage_tables(src, dst)
    assert (dst / "executed_queries.jsonl").is_file()
    assert (dst / "gather_raw" / "l-001.lead.json").is_file()
    assert (dst / "gather_raw" / "l-001" / "0.json").is_file()


def test_stage_tables_queryless_run_is_noop(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    dst = tmp_path / "dst"
    lr.stage_tables(src, dst)  # no tables → no error
    assert not (dst / "executed_queries.jsonl").exists()


def test_lead_ids_from_companion_filters_resolution_references():
    """A `:R` resolution row's comma-joined lead reference is surfaced under
    `findings` by the parser but must NOT be treated as a `:L` lead id."""
    companion = {
        "findings": [
            {"id": "l-001"},
            {"id": "l-002"},
            {"id": "l-001,l-002,l-003,l-004"},  # resolution lead-reference list
            {"id": None},
            {"no_id": True},
        ]
    }
    assert lr._lead_ids_from_companion(companion) == {"l-001", "l-002"}


# --------------------------------------------------------------------------
# load_summaries + summaries join/render (#311)
# --------------------------------------------------------------------------


def test_load_summaries_missing_file_is_empty(tmp_path):
    assert lr.load_summaries(tmp_path / "run") == []


def test_load_summaries_parses_rows_in_order(tmp_path):
    run = tmp_path / "run"
    _summary(run, "l-001", 0, 0, label="a")
    # second row written raw to exercise multi-tool `tools` parsing
    with (run / "summaries.jsonl").open("a") as fh:
        fh.write(json.dumps(
            {"lead_id": "l-001", "payload_seq": 0, "summary_seq": 1, "label": "b",
             "tools": ["jq", "sort", "uniq"], "snippet": "jq . f | sort | uniq",
             "output": "x", "exit_code": 0, "output_status": "ok"}
        ) + "\n")
    rows = lr.load_summaries(run)
    assert [r.summary_seq for r in rows] == [0, 1]
    assert [r.label for r in rows] == ["a", "b"]
    assert rows[0].payload_seq == 0
    assert rows[1].tools == ["jq", "sort", "uniq"]


def test_load_summaries_skips_malformed_and_lead_less(tmp_path):
    run = tmp_path / "run"
    run.mkdir(parents=True)
    (run / "summaries.jsonl").write_text(
        "\n".join(
            [
                "",  # blank
                "not json",  # non-JSON
                json.dumps([1, 2]),  # non-dict
                json.dumps({"payload_seq": 0, "label": "x"}),  # no lead_id
                json.dumps(
                    {"lead_id": "l-001", "payload_seq": 0, "summary_seq": 0,
                     "label": "ok", "snippet": "jq . f", "output": "1",
                     "exit_code": 0, "output_status": "ok"}
                ),
            ]
        )
    )
    rows = lr.load_summaries(run)
    assert len(rows) == 1
    assert rows[0].label == "ok"


def test_load_summaries_null_payload_seq(tmp_path):
    run = tmp_path / "run"
    _summary(run, "l-001", None, 0)
    rows = lr.load_summaries(run)
    assert rows[0].payload_seq is None


def test_joined_nests_summaries_on_lead_seq_sorted(tmp_path):
    run = tmp_path / "run"
    _lead(run, "l-001", "g1", ["d1"])
    _query(run, "l-001", 0)
    _summary(run, "l-001", 0, 1, label="second")
    _summary(run, "l-001", 0, 0, label="first")
    jl = lr.joined(run)
    assert len(jl) == 1
    assert [s.label for s in jl[0].summaries] == ["first", "second"]


def test_joined_summary_only_lead_surfaces_as_orphan(tmp_path):
    # A summary whose lead has no sidecar and no query must not be dropped.
    run = tmp_path / "run"
    _summary(run, "l-009", 0, 0, label="orphaned")
    jl = lr.joined(run)
    assert len(jl) == 1
    assert jl[0].lead_id == "l-009"
    assert jl[0].orphan is True
    assert [s.label for s in jl[0].summaries] == ["orphaned"]


def test_render_joined_yaml_nests_summary_code_not_value(tmp_path):
    import yaml

    run = tmp_path / "run"
    _lead(run, "l-001", "the goal", ["dim"])
    _query(run, "l-001", 0)
    _summary(run, "l-001", 0, 0, label="distinct-users",
             snippet="jq 'length' gather_raw/l-001/0.json", output="42")
    doc = yaml.safe_load(lr.render_joined_yaml(run))
    summ = doc["leads"][0]["queries"][0]["summaries"]
    assert summ == [
        {"label": "distinct-users",
         "snippet": "jq 'length' gather_raw/l-001/0.json",
         "output_status": "ok"}
    ]
    # pure A: the recorded value is never rendered.
    assert "output" not in summ[0]
    assert "42" not in lr.render_joined_yaml(run)


def test_render_joined_yaml_unattached_summaries(tmp_path):
    import yaml

    run = tmp_path / "run"
    _lead(run, "l-001", "g", ["d"])
    _query(run, "l-001", 0)
    _summary(run, "l-001", None, 0, label="no-payload")  # payload_seq None
    _summary(run, "l-001", 7, 1, label="no-such-seq")    # seq with no query
    doc = yaml.safe_load(lr.render_joined_yaml(run))
    lead = doc["leads"][0]
    assert "summaries" not in lead["queries"][0]
    labels = {s["label"] for s in lead["unattached_summaries"]}
    assert labels == {"no-payload", "no-such-seq"}


def test_stage_tables_copies_summaries(tmp_path):
    run = tmp_path / "run"
    _lead(run, "l-001", "g", ["d"])
    _query(run, "l-001", 0)
    _summary(run, "l-001", 0, 0)
    dst = tmp_path / "staged"
    lr.stage_tables(run, dst)
    assert (dst / "summaries.jsonl").is_file()
    assert lr.load_summaries(dst)[0].lead_id == "l-001"
