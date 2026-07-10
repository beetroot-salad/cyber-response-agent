"""Tests for the gather capture wrapper (defender/scripts/gather_tools/record_query.py).

Pins the deterministic-capture contract: query_id comes verbatim from the
dispatch (`--query-id`, the agent's catalog binding) and `system` is taken from
`--system` or derived generically from the inner adapter command (no hardcoded
system/verb tables), params are parsed generically from argv, per-lead canonical
addressing fixes the filename-drift silent drop, and the inner command passes
straight through. `--lead` is the `:L` row id (`l-NNN`), used as the per-lead
group dir and the `lead_id` FK. `--run-dir` defaults to `$DEFENDER_RUN_DIR`.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_RQ_PATH = Path(__file__).resolve().parents[1] / "scripts" / "gather_tools" / "record_query.py"
_spec = importlib.util.spec_from_file_location("record_query", _RQ_PATH)
ge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ge)


# --- parse_params: generic, no per-system tables ---

def test_parse_params_single_positional_and_boolean_flag():
    p = ge.parse_params(["python3", "/x/cmdb_cli.py", "host-lookup", "web-1", "--verbose"])
    assert p == {"arg0": "web-1", "verbose": True}


def test_parse_params_two_positionals():
    p = ge.parse_params(["/x/host_query.py", "fim-checksum", "db-1", "/etc/passwd", "--verbose"])
    assert p == {"arg0": "db-1", "arg1": "/etc/passwd", "verbose": True}


def test_parse_params_value_flags():
    p = ge.parse_params(
        ["wazuh_cli.py", "query", "--query", "rule.id:5503", "--limit", "20", "--verbose"]
    )
    assert p == {"query": "rule.id:5503", "limit": "20", "verbose": True}


def test_parse_params_short_flag_with_value():
    # `-q` is a real wazuh_cli short form for --query; it must capture its value,
    # not get dropped as a bare positional.
    p = ge.parse_params(["wazuh_cli.py", "query", "-q", "rule.id:5503", "--verbose"])
    assert p == {"q": "rule.id:5503", "verbose": True}


def test_parse_params_unknown_shape_does_not_raise():
    # No `.py` script token — still yields a dict rather than raising.
    assert isinstance(ge.parse_params(["python3", "-c", "print(1)"]), dict)


# --- payload_status ---

def test_payload_status():
    assert ge.payload_status(0, '{"a":1}') == "ok"
    assert ge.payload_status(0, "   \n") == "empty"
    assert ge.payload_status(3, "anything") == "error"


# --- end-to-end main(): real subprocess, addressing, passthrough, exit ---

def _fake_cli(tmp_path: Path, name: str, stdout: str, exit_code: int = 0) -> Path:
    cli = tmp_path / name
    cli.write_text(
        "import sys\n"
        f"sys.stdout.write({stdout!r})\n"
        f"sys.exit({exit_code})\n"
    )
    return cli


def test_main_writes_payload_record_and_passes_through(tmp_path, capsys):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "cmdb_cli.py", '{"name":"web-1","role":"web"}')

    rc = ge.main(["--run-dir", str(run_dir), "--lead", "l-003",
                  "--system", "stub-cmdb", "--query-id", "stub-cmdb.host-lookup", "--",
                  sys.executable, str(cli), "host-lookup", "web-1", "--verbose"])

    assert rc == 0
    payload = run_dir / "gather_raw" / "l-003" / "0.json"
    assert payload.is_file()
    assert json.loads(payload.read_text())["name"] == "web-1"

    rows = [json.loads(ln) for ln in (run_dir / "executed_queries.jsonl").read_text().splitlines()]
    assert len(rows) == 1
    r = rows[0]
    assert r["lead_id"] == "l-003"
    assert r["seq"] == 0
    assert r["system"] == "stub-cmdb"
    assert r["query_id"] == "stub-cmdb.host-lookup"
    assert r["verb"] == "host-lookup"
    assert r["params"] == {"arg0": "web-1", "verbose": True}
    assert r["payload_path"] == "gather_raw/l-003/0.json"
    assert r["payload_status"] == "ok"
    # passthrough: the CLI's stdout reaches the wrapper's stdout
    assert '"name":"web-1"' in capsys.readouterr().out


def test_main_records_system_and_query_id_verbatim(tmp_path):
    # The CLI filename ("host_query.py") does NOT match the catalog system
    # ("host-query"); the wrapper must trust --system / --query-id rather than
    # derive from argv. This pins the portability fix.
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "host_query.py", "uid=1003\n")
    ge.main(["--run-dir", str(run_dir), "--lead", "l-001",
             "--system", "host-query", "--query-id", "host-query.proc-tree", "--",
             sys.executable, str(cli), "proc-tree", "db-1"])
    row = json.loads((run_dir / "executed_queries.jsonl").read_text().splitlines()[0])
    assert row["system"] == "host-query"
    assert row["query_id"] == "host-query.proc-tree"
    assert row["verb"] == "proc-tree"


def test_main_per_lead_seq_increments(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "host_query.py", "uid=1003\n")
    ge.main(["--run-dir", str(run_dir), "--lead", "l-002",
             "--system", "host-query", "--query-id", "host-query.proc-tree", "--",
             sys.executable, str(cli), "proc-tree", "db-1"])
    ge.main(["--run-dir", str(run_dir), "--lead", "l-002",
             "--system", "host-query", "--query-id", "host-query.passwd", "--",
             sys.executable, str(cli), "passwd", "db-1"])
    rows = [json.loads(ln) for ln in (run_dir / "executed_queries.jsonl").read_text().splitlines()]
    assert [r["seq"] for r in rows] == [0, 1]
    assert (run_dir / "gather_raw" / "l-002" / "0.json").is_file()
    assert (run_dir / "gather_raw" / "l-002" / "1.json").is_file()


def test_main_adhoc_query_id(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "wazuh_cli.py", '{"hits":[]}')
    ge.main(["--run-dir", str(run_dir), "--lead", "l-001",
             "--system", "wazuh", "--query-id", "ad-hoc", "--",
             sys.executable, str(cli), "query", "--query", 'rule.id:5503', "--verbose"])
    row = json.loads((run_dir / "executed_queries.jsonl").read_text().splitlines()[0])
    assert row["query_id"] == "ad-hoc"
    assert row["params"] == {"query": "rule.id:5503", "verbose": True}


def test_main_requires_query_id(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "cmdb_cli.py", "{}")
    # --query-id is still required (the agent's catalog binding); missing it is a
    # usage error (exit 2), nothing executed — even though --system would derive.
    rc = ge.main(["--run-dir", str(run_dir), "--lead", "l-001", "--",
                  sys.executable, str(cli), "host-lookup", "web-1"])
    assert rc == 2
    assert not (run_dir / "executed_queries.jsonl").exists()


# --- derive_system: generic, no per-system table ---

def test_derive_system_from_defender_shim():
    assert ge.derive_system(["defender-elastic", "query", "x"]) == "elastic"
    assert ge.derive_system(["defender-change-mgmt", "list-changes"]) == "change-mgmt"
    assert ge.derive_system(["defender-host-state", "container-inspect", "c1"]) == "host-state"


def test_derive_system_from_cli_path():
    assert ge.derive_system(["python3", "/x/cmdb_cli.py", "host-lookup", "web-1"]) == "cmdb"


def test_derive_system_multiword_cli_path_normalizes_underscore():
    # A multi-word adapter file uses `_`, but the canonical system name and the
    # `defender-<system>` shim use `-`; the path form must agree with the shim
    # form so the queries-table join key is stable across both.
    assert ge.derive_system(["python3", "/x/host_state_cli.py", "inspect", "c1"]) == "host-state"
    assert ge.derive_system(["/x/change_mgmt_cli.py", "list"]) == "change-mgmt"
    assert ge.derive_system(["python3", "/x/threat_intel_cli.py", "lookup"]) == "threat-intel"


def test_derive_system_ignores_stray_tokens_before_shim():
    # A path/flag value that merely starts with `defender-` or ends in `_cli.py`
    # must not pre-empt the real adapter shim that follows it.
    assert ge.derive_system(["--out", "defender-runs/x", "defender-cmdb", "q"]) == "cmdb"
    assert ge.derive_system(["FOO=/x/elastic_cli.py", "defender-cmdb", "q"]) == "cmdb"


def test_derive_system_skips_non_adapter_and_unknown():
    # record-query/invlang are not lead systems.
    assert ge.derive_system(["defender-invlang", "--tags"]) is None
    assert ge.derive_system(["echo", "hi"]) is None


def test_main_derives_system_from_inner_when_flag_omitted(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "cmdb_cli.py", '{"name":"web-1"}')
    # No --system: derived from the cmdb_cli.py path token.
    rc = ge.main(["--run-dir", str(run_dir), "--lead", "l-001",
                  "--query-id", "cmdb.host-lookup", "--",
                  sys.executable, str(cli), "host-lookup", "web-1"])
    assert rc == 0
    row = json.loads((run_dir / "executed_queries.jsonl").read_text().splitlines()[0])
    assert row["system"] == "cmdb"


def test_main_derives_multiword_system_from_cli_path(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "host_state_cli.py", "{}")
    # No --system: derived (and normalized `_`→`-`) from the host_state_cli.py path.
    rc = ge.main(["--run-dir", str(run_dir), "--lead", "l-001",
                  "--query-id", "host-state.inspect", "--",
                  sys.executable, str(cli), "inspect", "c1"])
    assert rc == 0
    row = json.loads((run_dir / "executed_queries.jsonl").read_text().splitlines()[0])
    assert row["system"] == "host-state"


def test_main_explicit_system_overrides_derivation(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "cmdb_cli.py", "{}")
    ge.main(["--run-dir", str(run_dir), "--lead", "l-001",
             "--system", "stub-cmdb", "--query-id", "stub-cmdb.host-lookup", "--",
             sys.executable, str(cli), "host-lookup", "web-1"])
    row = json.loads((run_dir / "executed_queries.jsonl").read_text().splitlines()[0])
    assert row["system"] == "stub-cmdb"


def test_main_errors_when_system_underivable_and_flag_omitted(tmp_path, capsys):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "probe.py", "{}")  # no _cli.py / defender- token
    rc = ge.main(["--run-dir", str(run_dir), "--lead", "l-001",
                  "--query-id", "ad-hoc", "--", sys.executable, str(cli), "x"])
    assert rc == 2
    assert "could not be derived" in capsys.readouterr().err
    assert not (run_dir / "executed_queries.jsonl").exists()


# --- --run-dir defaults from $DEFENDER_RUN_DIR ---

def test_main_defaults_run_dir_from_env(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    monkeypatch.setenv("DEFENDER_RUN_DIR", str(run_dir))
    cli = _fake_cli(tmp_path, "cmdb_cli.py", "{}")
    # No --run-dir: defaults to $DEFENDER_RUN_DIR.
    rc = ge.main(["--lead", "l-001", "--query-id", "cmdb.host-lookup", "--",
                  sys.executable, str(cli), "host-lookup", "web-1"])
    assert rc == 0
    assert (run_dir / "executed_queries.jsonl").is_file()


def test_main_errors_when_no_run_dir(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("DEFENDER_RUN_DIR", raising=False)
    cli = _fake_cli(tmp_path, "cmdb_cli.py", "{}")
    rc = ge.main(["--lead", "l-001", "--query-id", "cmdb.host-lookup", "--",
                  sys.executable, str(cli), "host-lookup", "web-1"])
    assert rc == 2
    assert "DEFENDER_RUN_DIR is unset" in capsys.readouterr().err


def test_main_propagates_nonzero_exit_and_error_status(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "cmdb_cli.py", "", exit_code=3)
    rc = ge.main(["--run-dir", str(run_dir), "--lead", "l-001",
                  "--system", "stub-cmdb", "--query-id", "stub-cmdb.host-lookup", "--",
                  sys.executable, str(cli), "host-lookup", "nope"])
    assert rc == 3
    row = json.loads((run_dir / "executed_queries.jsonl").read_text().splitlines()[0])
    assert row["exit_code"] == 3
    assert row["payload_status"] == "error"
    # exit 3 is not an infra code → an agent-fixable mistake.
    assert row["error_class"] == "agent-fixable"


def test_error_class_recorded_per_exit_code(tmp_path):
    """The row carries the derived failure taxonomy: None on success, 'infra' for
    a down system (2; and the synthesized 124 timeout), 'agent-fixable' for a
    query error (1) or a CLI-usage error (64)."""
    cases = {0: None, 1: "agent-fixable", 2: "infra", 64: "agent-fixable"}
    for code, expected in cases.items():
        run_dir = tmp_path / f"run{code}"
        run_dir.mkdir()
        cli = _fake_cli(tmp_path, f"cmdb_cli_{code}.py", "out\n", exit_code=code)
        ge.main(["--run-dir", str(run_dir), "--lead", "l-001", "--system", "cmdb",
                 "--query-id", "cmdb.host-lookup", "--",
                 sys.executable, str(cli), "host-lookup", "x"])
        row = json.loads((run_dir / "executed_queries.jsonl").read_text().splitlines()[0])
        assert row["error_class"] == expected, (code, row["error_class"])
    # capture() synthesizes rc=124 on a hung adapter → infra (the breaker forgives it).
    assert ge.error_class_for_exit(124) == "infra"


# --- size-safety: oversized pass-through is truncated, payload still persisted ---

def _big_hits_payload(n: int) -> str:
    return json.dumps({"hits": [{"i": i, "message": f"event {i}", "pad": "x" * 50} for i in range(n)]})


def test_build_truncated_view_samples_records(tmp_path):
    payload = _big_hits_payload(200)
    view = ge.build_truncated_view(payload, "gather_raw/l-001/0.json", tmp_path)
    assert "200 records" in view
    assert view.count("sample[") == ge.PASSTHROUGH_SAMPLE_COUNT
    assert "jq" in view
    assert str(tmp_path / "gather_raw/l-001/0.json") in view


def test_build_truncated_view_non_json_falls_back_to_chars(tmp_path):
    view = ge.build_truncated_view("x" * 5000, "gather_raw/l-001/0.json", tmp_path)
    assert "bytes — pass-through truncated" in view
    assert "sample[" not in view


def test_build_truncated_view_capped_envelope_points_counts_at_total(tmp_path):
    # A capped payload (`total` >> returned): the on-disk payload is a
    # SAMPLE, so the view reports the exact `total`, frames the file as a sample,
    # and must NOT tell the agent to jq-`length` it (that would report the cap as
    # the count — the meaning-flip the returned-doc cap introduces).
    payload = json.dumps({
        "index": "logs-*", "total": 2471, "returned": 20, "truncated": True,
        "hits": [{"i": i, "message": f"event {i}"} for i in range(20)],
    })
    view = ge.build_truncated_view(payload, "gather_raw/l-001/0.json", tmp_path)
    assert "2471 total matches (EXACT" in view
    assert "20-doc SAMPLE" in view
    assert "| length" not in view                  # never count the sample
    assert view.count("sample[") == ge.PASSTHROUGH_SAMPLE_COUNT


def test_build_truncated_view_complete_envelope_is_not_flagged_sampled(tmp_path):
    # total == returned (the result set is complete, not capped) → the ordinary
    # "compute over the payload" framing, not the sample/`total` framing.
    payload = json.dumps({
        "total": 3, "returned": 3, "truncated": False,
        "hits": [{"i": i} for i in range(3)],
    })
    view = ge.build_truncated_view(payload, "gather_raw/l-001/0.json", tmp_path)
    assert "FIELD-SHAPE sample" in view
    assert "total matches (EXACT" not in view


def test_main_samples_record_list_and_persists_full(tmp_path, capsys):
    # A record-list payload is ALWAYS reduced to a field-shape sample (count +
    # first few records + disk pointer), regardless of size — the full dump never
    # enters the passthrough. The full payload is still persisted on disk.
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    big = _big_hits_payload(100)
    cli = _fake_cli(tmp_path, "elastic_cli.py", big)
    rc = ge.main(["--run-dir", str(run_dir), "--lead", "l-001",
                  "--system", "elastic", "--query-id", "elastic.q", "--",
                  sys.executable, str(cli), "query", "--verbose"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "FIELD-SHAPE sample" in out
    assert "100 records" in out
    assert "sample[0]" in out
    assert out.count("sample[") == ge.PASSTHROUGH_SAMPLE_COUNT
    assert big not in out                          # the full dump never passes through
    persisted = (run_dir / "gather_raw" / "l-001" / "0.json").read_text()
    assert persisted == big


def test_main_small_record_list_is_still_sampled(tmp_path, capsys, monkeypatch):
    # Even a tiny record-list is sampled, not dumped verbatim — so a re-sent
    # context never carries the raw events (the cache-read tax this closes).
    monkeypatch.setenv("DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES", "65536")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "elastic_cli.py", '{"hits":[{"i":1}]}')
    rc = ge.main(["--run-dir", str(run_dir), "--lead", "l-001",
                  "--system", "elastic", "--query-id", "elastic.q", "--",
                  sys.executable, str(cli), "query", "--verbose"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "FIELD-SHAPE sample" in out
    assert "1 records" in out


def test_main_non_list_object_passes_through_verbatim(tmp_path, capsys, monkeypatch):
    # A single object (not a record list) IS the answer and is small — it passes
    # through whole; there is nothing to "sample".
    monkeypatch.setenv("DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES", "65536")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "identity_cli.py", '{"user":"dev.dana","authorized_hosts":["jump-box-1"]}')
    rc = ge.main(["--run-dir", str(run_dir), "--lead", "l-001",
                  "--system", "identity", "--query-id", "identity.profile", "--",
                  sys.executable, str(cli), "profile", "dev.dana"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "FIELD-SHAPE sample" not in out
    assert '{"user":"dev.dana","authorized_hosts":["jump-box-1"]}' in out


# --- --lead validation (mirrors record_lead's claim-side guard) ---

def test_main_rejects_invalid_lead_id(tmp_path, capsys):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "cmdb_cli.py", "{}")
    for bad in ("../../etc", "/etc", "l 1", "x-001", ""):
        rc = ge.main(["--run-dir", str(run_dir), "--lead", bad,
                      "--system", "stub-cmdb", "--query-id", "stub-cmdb.x", "--",
                      sys.executable, str(cli), "x", "a"])
        assert rc == 2, f"expected reject for {bad!r}"
    # No table or payload escaped the run dir.
    assert not (run_dir / "executed_queries.jsonl").exists()


# --- seq stays monotonic even when a payload write fails (no (lead,seq) reuse) ---

def test_main_seq_monotonic_after_failed_payload_write(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cli = _fake_cli(tmp_path, "cmdb_cli.py", "{}")

    real_write = Path.write_text
    calls = {"n": 0}

    def flaky_write(self, data, *a, **k):
        # Fail only the FIRST payload write (a .json under gather_raw/), so its
        # row is still appended with payload_path: null and no 0.json exists.
        if self.suffix == ".json" and "gather_raw" in str(self) and calls["n"] == 0:
            calls["n"] = 1
            raise OSError("disk full")
        return real_write(self, data, *a, **k)

    monkeypatch.setattr(Path, "write_text", flaky_write)
    ge.main(["--run-dir", str(run_dir), "--lead", "l-001", "--system", "s",
             "--query-id", "s.a", "--", sys.executable, str(cli), "a"])
    ge.main(["--run-dir", str(run_dir), "--lead", "l-001", "--system", "s",
             "--query-id", "s.b", "--", sys.executable, str(cli), "b"])
    monkeypatch.undo()

    rows = [json.loads(ln) for ln in (run_dir / "executed_queries.jsonl").read_text().splitlines()]
    assert [r["seq"] for r in rows] == [0, 1]          # no reuse
    assert rows[0]["payload_path"] is None             # first write failed
    assert rows[1]["payload_path"] == "gather_raw/l-001/1.json"
