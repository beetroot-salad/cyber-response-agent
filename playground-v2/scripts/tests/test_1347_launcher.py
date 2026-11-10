"""#1347 r6.4.1 A1-A7: the launcher readies a variant's frozen copy, runs the agent on it and writes the row.

Entry point bound by this contract: `playground-v2/scripts/launch_frozen.py::launch(case_dir, *,
freezes_dir, tenant_settings, index, parts_dir, lock_store, es, ops, run_fn, clock, env, tenant,
knowledge=None, reference=False, lock_token=None) -> run_id`.

* `tenant_settings` is the lab tenant's `settings/` directory (D24). The patterns the launcher works
  on are the freeze's (`freeze.yaml["patterns"]`, a list `[events, alerts]`); it refuses a case, before
  anything, when they differ from the ones `tenant_settings/systems/elastic/config.env` has now. There is
  no `patterns` parameter and no built-in default.

* `es` is the FROZEN cluster through the chaos seam's `es_request(method, path, body=None)`; the
  launcher talks to it directly, never through the frozen proxy.
* `ops` is the REAL lab layer, `lab_ops.LabOps` (r6.4.3 C-rig), built by `_lab_fakes.LabRig` with only its
  outer edge faked: docker through `run=` (`_rig_docker.RigDocker`) and the frozen cluster reached through
  the real curl path, `ops.frozen_es()` (the rig passes it as `es`). Tests observe what the layer sent to
  docker and the cluster and the state those fakes hold: containers, volumes, files in the engine, requests.
* `case_dir` holds alert.json, ground_truth.yaml and case.yaml (freeze, alert, age, overlay
  `None | {mutations, span_start}`, counts, content, confirmed); the freeze is
  `freezes_dir/<freeze>/freeze.yaml`; parts are `parts_dir/<freeze>/<name>`, digests bare hex.
* `lock_token`: a token already holding the frozen-engine lock (make-a-case's); the launch joins it
  and does not release it.
* The row's `binding` comes from the scorer: `evaluations.held_out.binding(freeze_doc, case_doc)`
  over the parsed freeze.yaml and case.yaml, imported, not re-implemented (A8).

Tests read the copy's END STATE from `_lab_fakes.FakeCluster`, not a request sequence (A3).

r6.4.3: D25 (every restore goes into a fresh node: the old node container and its data volume are discarded,
nothing is closed or deleted to make room, the copy-state marker lives in the engine's state volume
`lab-engine-state`) and D15 revised (the node's wall-clock shim reads its offset from a file named by the
node's `V2_CLOCK_OFFSET_FILE`; the node starts with it already holding T - now; the launcher rewrites it to
T - now as the last lab step before the agent runs; a launch never restarts the node for its clock).

r6.4.3 settlements, the offset file: a fixed-width record of 24 bytes, a signed decimal integer number of
seconds padded with spaces and ending in a newline. It is created at that size before the node starts and only
ever rewritten in place at byte 0 (the same file, never truncated), so the shim's mapping never runs past the
file's end. The rig docker records how each write opened the file (`>` truncates; `1<>` and `dd
conv=notrunc` write in place).
"""
from __future__ import annotations

import ast
import copy
import json
import re
from datetime import timedelta
from pathlib import Path

import pytest
import yaml
from _lab_fakes import (AUTH, AUTH_AFTER_T, AUTH_IN_SPAN, ALERTS, ALERTS_PATTERN, DATA_DROP, EVENTS, FREEZE_ID,
                        LIVE_PROXY_URL, NGINX, PARTS, REPO, ROW_KEYS, RULES_PART, RUN_ID, SCHEMA_DRIFT,
                        SLUG, SPAN_START, SYSLOG, SYSLOG_AFTER_T, SYSLOG_IN_SPAN, T, FaultJournal, LabRig,
                        canonical_digest, expected_copy, expected_variant, instant, is_clean_marker)

LAUNCH = Path(__file__).resolve().parents[1] / "launch_frozen.py"
KINDS = ["none", "drop", "drift", "cmdb"]


def _once(pred):
    seen = []

    def fail(method, path, body):
        if pred(method, path, body) and not seen:
            seen.append(1)
            return True
        return False

    return fail


def _opt(argv, flag):
    assert flag in argv, f"{flag} missing from {argv}"
    return argv[argv.index(flag) + 1]


def _names_the_frozen_proxy(rig, url):
    """`url` addresses the frozen proxy container the launch started (by its name or hostname)."""
    from urllib.parse import urlsplit
    proxy = rig.proxy()
    assert proxy is not None, "no frozen proxy was started"
    argv = proxy.argv
    names = {proxy.name} | {argv[i + 1] for i, a in enumerate(argv[:-1]) if a in ("--hostname", "-h", "--network-alias")}
    return urlsplit(url).hostname in names


def _no_lab_traffic(rig):
    """Nothing reached the lab: no docker call, no cluster request."""
    assert rig.docker.calls == [] and not rig.cluster.requests, (rig.docker.calls[:3], rig.cluster.requests[:3])


def _mutating(rig):
    return [m for m in rig.cluster.mutations if m["kind"] in ("delete_by_query", "reindex")]


# -- a scored launch ------------------------------------------------------------------------------


def test_a_scored_launch_runs_the_agent_as_of_T_on_the_frozen_proxy_and_writes_the_bound_row(tmp_path):
    """A7/O9/O5: the run is handed `--as-of T` and the frozen proxy's own url; one valid row
    carries the binding; the row is on disk before teardown; the engine lock is held in the run."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    older = json.dumps({"slug": SLUG, "run_id": "older", "binding": "x" * 64, "verdict": "valid",
                        "reason": "", "verified_at": "2026-10-20T11:00:00Z", "knowledge": "k0"}) + "\n"
    rig.index.write_text(older)

    assert rig.launch() == RUN_ID
    j = rig.journal

    assert instant(_opt(rig.argv, "--as-of")) == instant(T)
    assert not {"--update-ticket", "--episode", "--world", "--arrived-by"} & set(rig.argv)
    assert _opt(rig.argv, "--tenant") == "tenant-1" and _opt(rig.argv, "--knowledge-commit") == "abc1234"
    assert str(rig.case_dir / "alert.json") in rig.argv and all(isinstance(a, str) for a in rig.argv)
    url = rig.env["DEFENDER_CREDENTIAL_PROXY_URL"]
    assert url != LIVE_PROXY_URL and _names_the_frozen_proxy(rig, url), url
    assert rig.docker.of_kind("proxy-start")[0]["j"] < j.first("run")
    assert rig.index.read_text().startswith(older), "an existing row was rewritten"
    first, row = rig.rows()
    assert set(row) == ROW_KEYS and isinstance(row["reason"], str)
    assert (row["slug"], row["run_id"], row["binding"], row["verdict"], row["knowledge"]) == (
        SLUG, RUN_ID, rig.binding(), "valid", "abc1234")
    assert instant(row["verified_at"]) > instant("2026-11-08T12:00:00Z")
    assert [json.loads(x) for x in rig.teardown_seen()["index"].splitlines()] == [first, row]
    assert rig.lock_in_run and "frozen-engine" not in rig.store.records


def test_the_binding_is_the_scorers_not_a_second_formula(tmp_path):
    """A8: launch_frozen imports the scorer's binding function from `evaluations`. (Its value is
    cross-checked against an independent formula in the test above.)"""
    tree = ast.parse(LAUNCH.read_text())
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)
                and (n.module or "").startswith("evaluations") for a in n.names}
    assert "binding" in imported, imported


def test_the_row_binding_follows_the_case_file_as_it_is_on_disk_confirmation_included(tmp_path):
    """A8: re-confirming the case changes the case digest, so a later launch's row has another binding."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    rig.launch()
    rig.write_expected_case("none", confirmed=False)
    rig.launch(reference=True)
    case = rig.case()
    case["confirmed"] = {"by": "op2", "at": "2026-11-10T10:00:00Z", "reference_run": "r1"}
    (rig.case_dir / "case.yaml").write_text(yaml.safe_dump(case))
    rig.launch()

    first, second = rig.rows()
    assert first["binding"] != second["binding"] == rig.binding()


def test_a_run_without_a_knowledge_pin_gets_no_knowledge_flag_and_the_row_says_none(tmp_path):
    """A8: the row records the knowledge revision the run used; without a pin there is none."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    rig.launch(knowledge=None)

    assert "--knowledge-commit" not in rig.argv
    assert rig.rows()[0]["knowledge"] in (None, "")


def test_the_agents_environment_changes_only_the_proxy_address_and_names_no_freeze(tmp_path):
    """P4/A7: of the operator's environment only DEFENDER_CREDENTIAL_PROXY_URL differs, and
    nothing the launcher adds names a freeze, snapshot, fault or the frozen engine."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("drop")
    rig.launch()

    operator = {"PATH": "/usr/bin", "DEFENDER_CREDENTIAL_PROXY_URL": LIVE_PROXY_URL}
    changed = {k for k in rig.env if rig.env[k] != operator.get(k)}
    assert changed == {"DEFENDER_CREDENTIAL_PROXY_URL"}, changed
    for word in ("freeze", "snapshot", "overlay", "fault", "chaos", "engine", FREEZE_ID, SLUG):
        assert word not in "".join(f"{k}={v}" for k, v in rig.env.items() if k not in operator).lower()


# -- readying the variant (A1, A3) ------------------------------------------------------------------


@pytest.mark.parametrize("kind", KINDS)
def test_a_launch_leaves_exactly_the_variants_end_state_and_the_row_is_valid(tmp_path, kind):
    """A3: every document in the copy is what the overlay promises (base overlay everywhere,
    fault overlay on the span); no scratch index or temporary pipeline is left; verdict valid."""
    rig = LabRig(tmp_path)
    rig.write_expected_case(kind)
    rig.launch()

    assert rig.cluster.state() == expected_copy(kind)
    assert rig.cluster.pipelines == {}
    assert [r["verdict"] for r in rig.rows()] == ["valid"], rig.rows()
    assert rig.cluster.restores == 1


def test_the_base_overlay_deletes_everything_stamped_after_T_from_every_pattern(tmp_path):
    """A3: events and alerts stamped after T are gone; the document stamped exactly at T stays."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    rig.launch()
    state = rig.cluster.state()

    assert not set(AUTH_AFTER_T) & set(state[AUTH]) and not set(SYSLOG_AFTER_T) & set(state[SYSLOG])
    assert "id-future" not in state[ALERTS] and "id-at-T" in state[ALERTS] and "auth-30" in state[AUTH]
    assert len(state[NGINX]) == 10, "an index with nothing after T is untouched"


def test_a_data_drop_removes_the_processors_victims_from_the_span_and_nothing_outside_it(tmp_path):
    """A3/O7: in-span syslog documents go exactly as the verbatim drop processor decides (both bound
    documents are in the span); an out-of-span document the same hash would drop survives; alerts stay."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("drop")
    rig.launch()
    state = rig.cluster.state()

    gone = set(SYSLOG_IN_SPAN) - set(state[SYSLOG])
    assert gone and gone < set(SYSLOG_IN_SPAN), "the fixture must drop some, not all, of the span"
    assert {"syslog-15", "syslog-25"} <= set(state[SYSLOG]) | gone       # the bound documents were in scope
    assert {"syslog-02", "syslog-13"} <= set(state[SYSLOG]), "documents before the span were touched"
    assert state[ALERTS] == expected_copy("none")[ALERTS]


def test_a_schema_drift_rewrites_span_events_and_the_alerts_derived_from_them_keeping_versions(tmp_path):
    """A3/D22: in-span auth documents (both bound documents) and the alerts whose ancestry reaches
    an in-span auth event carry the renamed field with _id and _version kept; an alert in the span by
    its own time but derived from an earlier event, and one derived from another dataset, are verbatim."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("drift")
    rig.launch()
    state, base = rig.cluster.state(), expected_copy("none")

    for doc_id in AUTH_IN_SPAN:
        version, source = state[AUTH][doc_id]
        assert "source.port" not in source and source["source.port_no"] == base[AUTH][doc_id][1]["source.port"]
        assert version == base[AUTH][doc_id][0]
    assert state[AUTH]["auth-20"][0] == 2, "a document's _version survives the rewrite"
    assert state[AUTH]["auth-17"] == base[AUTH]["auth-17"]
    assert state[ALERTS]["id-young"][0] == 3 and "source.port_no" in state[ALERTS]["id-young"][1]
    assert state[ALERTS]["id-derived-pre"] == base[ALERTS]["id-derived-pre"]
    assert state[ALERTS]["id-syslog-alert"] == base[ALERTS]["id-syslog-alert"]


def test_a_cmdb_stale_overlay_is_applied_at_stub_load_and_changes_no_document(tmp_path):
    """A3: the stub store loads with the case's resolved mutations; the cluster gets only the base overlay."""
    rig = LabRig(tmp_path)
    case = rig.write_expected_case("cmdb")
    rig.launch()

    stubs = rig.stubs()
    assert set(stubs) == {"cmdb", "threat-intel", "change-mgmt", "ticket-server", "identity"}, stubs
    assert all(instant(s["as_of"]) == instant(T) for s in stubs.values()), stubs
    flip = case["overlay"]["mutations"][0]
    assert stubs["cmdb"]["overlays"] == {flip["host"]: {flip["field"]: flip["new_value"]}}, stubs["cmdb"]
    assert not [m for m in rig.cluster.mutations if m["kind"] == "reindex"]


def test_a_variant_without_an_overlay_loads_the_stubs_with_no_mutations(tmp_path):
    """A3/O3: control for the test above; stubs are pinned at T either way."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    rig.launch()

    stubs = rig.stubs()
    assert len(stubs) == 5 and all(instant(s["as_of"]) == instant(T) for s in stubs.values()), stubs
    assert all(not s["overlays"] for s in stubs.values()), stubs


def test_the_copy_is_made_safe_before_it_is_changed(tmp_path):
    """A1/D8: the repository is registered readonly; ILM is stopped and each stream's lifecycle
    removed before the first overlay mutation; the repository is never written to."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("drift")
    rig.launch()
    cluster = rig.cluster

    assert cluster.repos[REPO]["settings"]["readonly"] is True
    assert not rig.es_at(lambda m, p: m in ("PUT", "POST") and p.startswith(f"/_snapshot/{REPO}/")
                         and not p.endswith("/_restore"))
    overlay = _mutating(rig)
    assert overlay
    for entry in overlay:
        assert entry["ilm"] != "RUNNING", entry
        assert entry["streams"] <= entry["lifecycle_off"], entry


def test_the_copy_state_marker_is_dirty_from_before_the_first_change_until_the_variant_is_ready(tmp_path):
    """A4: at every restore and overlay request the stored marker is not a clean one; afterwards it
    is clean and names the freeze."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("drop")
    rig.launch()

    for entry in rig.cluster.mutations:
        marker = entry["observed"]
        assert marker is None or marker["dirty"] is True, entry
        if entry["kind"] in ("delete_by_query", "reindex"):
            assert marker is not None and marker["dirty"] is True, entry
    assert is_clean_marker(rig.marker()), rig.marker()     # D25: the marker keeps the variant id and tallies


def test_the_launch_checks_the_copy_after_the_overlays_and_only_then_runs_the_agent(tmp_path):
    """O6 (D15's restart retired by D15 revised): health is awaited after the overlays, counts are read
    after that, the stubs are up, and only then does the agent run."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("drift")
    rig.launch()
    j = rig.journal

    last_overlay = max(i for i, m in enumerate(j) if m[0] == "es" and m[1][1] in ("/_reindex",)
                       or m[0] == "es" and m[1][1].endswith("/_delete_by_query"))
    health = rig.es_at(lambda m, p: p == "/_cluster/health")
    counts = rig.es_at(lambda m, p: p.endswith("/_count") or p.startswith("/_cat/indices"))
    assert last_overlay < health[-1] < max(counts) < j.first("run")
    assert rig.docker.of_kind("stub-start") and max(e["j"] for e in rig.docker.of_kind("stub-start")) < j.first("run")


# -- credentials (A9) ------------------------------------------------------------------------------


def test_the_read_only_user_gets_the_current_password_and_the_node_cert_is_mounted_before_the_proxy(tmp_path):
    """A9: each launch reads the password as it is then, creates the user with it and mounts the live
    node certificate, both before the frozen proxy starts; neither is written into a freeze part."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    parts_before = {p.name: p.read_bytes() for p in (rig.parts / FREEZE_ID).iterdir()}
    rig.launch()
    rig.password = "pw-rotated"
    rig.launch()

    assert [pw for pw, _ in rig.users()] == ["pw-0", "pw-rotated"], rig.users()
    assert all(up is False for _, up in rig.users()), rig.users()      # created before the proxy started
    starts = rig.docker.of_kind("proxy-start")
    assert len(starts) == 2
    for start in starts:      # when each launch's proxy starts, the node serving it reads the live certificate
        assert start["node_running"] and rig.certs_mounted(start["node"]), start
    assert {p.name: p.read_bytes() for p in (rig.parts / FREEZE_ID).iterdir()} == parts_before
    assert not any(b"pw-" in b for b in parts_before.values())
    after = (rig.freeze_dir / "freeze.yaml").read_text() + (rig.case_dir / "case.yaml").read_text()
    after += "".join(p.read_text(errors="ignore") for p in (rig.parts / FREEZE_ID).iterdir())
    assert "pw-0" not in after and "pw-rotated" not in after


# -- the marker (A4) -------------------------------------------------------------------------------


def test_a_clean_marker_for_the_same_variant_skips_the_restore_and_the_copy_stays_valid(tmp_path):
    """A4/A1: teardown keeps the ES data; the next launch of the same variant restores and overlays
    nothing and is valid."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("drop")
    rig.launch()
    after_first = len(rig.cluster.mutations)
    rig.launch()

    assert rig.cluster.restores == 1 and len(rig.cluster.mutations) == after_first
    assert [r["verdict"] for r in rig.rows()] == ["valid", "valid"]
    assert rig.cluster.state() == expected_copy("drop")


@pytest.mark.parametrize("first, second", [("drop", "none"), ("drift", "drop"), ("none", "drift")])
def test_another_variant_restores_the_whole_snapshot_leaving_no_residue_of_the_last(tmp_path, first, second):
    """A4: a clean marker of a different variant is not trusted; the second copy equals its own end state."""
    rig = LabRig(tmp_path)
    rig.write_expected_case(first)
    rig.launch()
    rig.write_expected_case(second)
    rig.launch()

    assert rig.cluster.restores == 2
    assert rig.cluster.state() == expected_copy(second)
    assert [r["verdict"] for r in rig.rows()] == ["valid", "valid"]


def test_an_overlay_that_died_midway_leaves_a_dirty_marker_and_the_next_launch_restores_it_all(tmp_path):
    """A4: the failed launch leaves no clean marker; the next launch restores the whole snapshot
    over the half-changed copy and ends valid."""
    rig = LabRig(tmp_path, fail=_once(lambda m, p, b: p.startswith("/_reindex")))
    rig.write_expected_case("drift")
    with pytest.raises(Exception):
        rig.launch()
    assert not is_clean_marker(rig.marker()), rig.marker()

    rig.launch()

    assert rig.cluster.restores == 2 and rig.cluster.state() == expected_copy("drift")
    assert [r["verdict"] for r in rig.rows()] == ["valid"]


def test_a_copy_with_no_marker_is_restored_whole_over_whatever_it_holds(tmp_path):
    """A4: an unknown copy state (no marker) is never trusted: stray and altered documents in an
    open index of the copy an earlier launch left are gone after the launch."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    rig.launch()
    rig.drop_marker()
    rig.cluster.put(AUTH, "auth-99", {"@timestamp": "2026-10-20T05:00:00Z", "message": "stray"})
    rig.cluster.put(AUTH, "auth-05", {"@timestamp": "2026-10-20T04:50:00Z", "message": "altered"})
    rig.cluster.put(NGINX, "nginx-99", {"@timestamp": "2026-10-20T05:00:00Z", "message": "stray"})
    rig.launch()

    assert rig.cluster.restores == 2 and rig.cluster.state() == expected_copy("none")
    assert [r["verdict"] for r in rig.rows()] == ["valid", "valid"]


def test_a_clean_marker_does_not_hide_a_copy_altered_behind_its_back(tmp_path):
    """A1/A4: the content digest catches what the marker cannot: a document changed in place after
    a valid launch makes the next launch of the same variant `stale`, naming the content."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    rig.launch()
    rig.cluster.put(NGINX, "nginx-03", {"@timestamp": "2026-10-20T05:30:00Z", "message": "GET /changed",
                                        "event.dataset": "nginx.access"})
    rig.launch()

    assert [r["verdict"] for r in rig.rows()] == ["valid", "stale"]
    assert "content" in rig.rows()[1]["reason"]


# -- stale (A2) ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("field, needle", [("counts", SYSLOG), ("content", "content"), ("alert", "alert")])
def test_a_copy_that_differs_from_what_the_case_recorded_is_a_stale_row_naming_it(tmp_path, field, needle):
    """A2/P2: a per-index count, the content digest or the copy's alert differing from case.yaml
    is `stale` with a reason naming it; the run still happens and gets its row."""
    rig = LabRig(tmp_path)
    case = rig.write_expected_case("drop")
    recorded = {"counts": {**case["counts"], SYSLOG: case["counts"][SYSLOG] + 1},
                "content": "f" * 64, "alert": "e" * 64}[field]
    rig.write_expected_case("drop", **{field: recorded})
    rig.launch()

    [row] = rig.rows()
    assert (row["verdict"], row["run_id"], row["binding"]) == ("stale", RUN_ID, rig.binding())
    assert needle in row["reason"], row


def test_a_restore_that_returns_other_documents_than_the_freeze_recorded_is_stale_not_a_failure(tmp_path):
    """O6/A2: the snapshot held one more document than the freeze counted: the restore completes and
    the overlay applies, so the evidence changed: a stale row, not a launch failure."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    rig.cluster.content[AUTH]["auth-extra"] = {"_version": 1, "_source": {
        "@timestamp": "2026-10-20T05:05:00Z", "message": "added after the freeze counted"}}
    rig.launch()

    [row] = rig.rows()
    assert row["verdict"] == "stale" and AUTH in row["reason"], row


# -- launch failure vs refusal (A2) ---------------------------------------------------------------------


def _launch_failures():
    def reindex(m, p, b):
        return p.startswith("/_reindex")

    return [
        pytest.param({"fail": lambda m, p, b: p.endswith("/_restore")}, None, "/_restore", id="restore"),
        pytest.param({"fail": lambda m, p, b: p.endswith("/_delete_by_query")}, None, "/_delete_by_query", id="base-overlay"),
        pytest.param({"fail": reindex}, None, "/_reindex", id="fault-overlay"),
        pytest.param({}, "marker-write", None, id="marker"),
        pytest.param({}, "stub-start", None, id="stubs"),
        pytest.param({}, "node-start", None, id="node-start"),
        pytest.param({}, "proxy-start", None, id="proxy"),
    ]


_NOT_A_REFUSAL = (AttributeError, TypeError, NameError, ImportError)


def _chain(exc):
    while exc is not None:
        yield exc
        exc = exc.__cause__ or exc.__context__


def _fails_to_launch(rig, injected=None):
    """The launch module loads first (a missing script fails here, outside the failure under test);
    the launch then raises, with the injected failure (when named) in the exception chain."""
    rig.launch_module
    with pytest.raises(Exception) as caught:
        rig.launch()
    assert not isinstance(caught.value, _NOT_A_REFUSAL + (AssertionError, NotImplementedError)), repr(caught.value)
    if injected:
        assert any(injected in str(e) for e in _chain(caught.value)), repr(caught.value)
    return caught.value


@pytest.mark.parametrize("rig_kw, ops_fail, reached", _launch_failures())
def test_a_copy_that_cannot_be_made_is_a_launch_failure_with_no_row(tmp_path, rig_kw, ops_fail, reached):
    """A2/O6: not stale: the failing step was reached, nothing runs, no row, nothing the launch started
    still serves (torn down), the lock is free and no clean marker is left. A docker-edge failure
    (`ops_fail`) is an effect the rig docker refuses: a marker write, a stub, node or proxy start."""
    rig = LabRig(tmp_path, **rig_kw, docker_fail={ops_fail} if ops_fail else None)
    rig.write_expected_case("drift")
    _fails_to_launch(rig, f"{ops_fail} failed" if ops_fail else f"{reached} failed")

    assert (ops_fail in rig.docker.injected) if ops_fail else rig.es_at(lambda m, p: reached in p)
    assert "run" not in rig.journal.ops() and rig.rows() == []
    assert rig.nothing_serving() == [] and "frozen-engine" not in rig.store.records
    if not ops_fail or ops_fail == "marker-write":     # a copy that was made stays clean when only a service failed
        assert not is_clean_marker(rig.marker()), rig.marker()


def test_a_cluster_that_never_turns_green_is_a_launch_failure_with_no_row(tmp_path):
    """O6: "wait for primaries active" gives up after polling health: no run, no row, torn down, lock free."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    rig.cluster.health_status = "red"
    _fails_to_launch(rig)

    assert len(rig.es_at(lambda m, p: p == "/_cluster/health")) >= 1, "health was never polled"
    assert "run" not in rig.journal.ops() and rig.rows() == [] and "frozen-engine" not in rig.store.records
    assert rig.nothing_serving() == []


def _damage(rig, how, name):
    part = rig.parts / FREEZE_ID / name
    part.unlink() if how == "missing" else part.write_bytes(b"tampered")


@pytest.mark.parametrize("how", ["missing", "altered"])
@pytest.mark.parametrize("name", sorted(PARTS))
def test_a_missing_or_altered_freeze_part_refuses_the_case_before_anything_and_names_it(tmp_path, how, name):
    """A2/O6/A5: every part, the detection-rules part included (the freeze's rules digest is
    re-verified at every launch): no cluster request, no stub load, no run, no row."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    _damage(rig, how, name)
    rig.launch_module  # a missing script fails here, outside the refusal being tested
    with pytest.raises(Exception, match=name) as caught:
        rig.launch()

    assert not isinstance(caught.value, (AttributeError, TypeError, NameError))
    assert RULES_PART in PARTS
    _no_lab_traffic(rig)
    assert rig.rows() == [] and "frozen-engine" not in rig.store.records


def test_a_snapshot_with_another_uuid_is_refused_before_the_copy_is_touched(tmp_path):
    """A2/O6: the freeze names its snapshot's UUID; a different one refuses the case: no restore,
    no overlay, no run, no row."""
    rig = LabRig(tmp_path, snapshot_uuid="another-uuid")
    rig.write_expected_case("none")
    rig.launch_module
    with pytest.raises(Exception, match="(?i)uuid"):
        rig.launch()

    assert rig.cluster.mutations == [] and rig.cluster.restores == 0
    assert "run" not in rig.journal.ops() and rig.rows() == [] and "frozen-engine" not in rig.store.records


@pytest.mark.parametrize("damage", ["unconfirmed", "no-freeze", "no-counts"])
def test_a_malformed_or_unconfirmed_case_is_refused_before_anything(tmp_path, damage):
    """A2: a scored launch of an unconfirmed case, a case naming a freeze that does not exist and a
    case.yaml missing a required key are refused with no cluster request, no run, no row."""
    rig = LabRig(tmp_path)
    case = rig.write_expected_case("none", confirmed=damage != "unconfirmed")
    if damage == "no-freeze":
        case["freeze"] = "f-nonexistent"
    if damage == "no-counts":
        del case["counts"]
    (rig.case_dir / "case.yaml").write_text(yaml.safe_dump(case))
    rig.launch_module
    with pytest.raises(Exception) as caught:
        rig.launch()

    assert not isinstance(caught.value, (AttributeError, TypeError, NameError))
    _no_lab_traffic(rig)
    assert rig.rows() == [] and "frozen-engine" not in rig.store.records


def test_a_fixture_without_a_case_file_is_not_a_case(tmp_path):
    """A2/O11: legacy fixtures (alert.json and ground truth only) are refused, not launched."""
    rig = LabRig(tmp_path)
    rig.launch_module
    with pytest.raises(Exception) as caught:
        rig.launch()

    assert not isinstance(caught.value, (AttributeError, TypeError, NameError))
    _no_lab_traffic(rig)
    assert rig.rows() == []


# -- the run and the row (O9) -----------------------------------------------------------------------------


def test_a_run_that_crashed_after_announcing_its_id_still_gets_a_row(tmp_path):
    """O9: a nonzero agent exit with an announced run id is a run; the scorer counts it wrong."""
    rig = LabRig(tmp_path, run_rc=1)
    rig.write_expected_case("none")
    rig.launch()

    assert [r["run_id"] for r in rig.rows()] == [RUN_ID]


def test_a_run_that_never_announced_its_id_gets_no_row_and_the_launch_cleans_up(tmp_path):
    """O9: no `run_id=` line means no row; teardown ran and the lock is free."""
    rig = LabRig(tmp_path, run_rc=1, run_out="Traceback (most recent call last):\n")
    rig.write_expected_case("none")
    rig.launch_module
    try:
        rig.launch()
    except (AttributeError, TypeError, NameError, ImportError):
        raise
    except Exception:  # noqa: BLE001 - raising or returning are both acceptable for a dead run
        pass

    assert rig.rows() == []
    assert rig.nothing_serving() == [] and rig.teardown_seen() is not None and "frozen-engine" not in rig.store.records


def test_an_interrupt_during_the_run_tears_down_and_frees_the_engine_without_a_row(tmp_path):
    """O9: Ctrl-C while the agent runs: teardown, lock released, no row."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")

    def interrupt():
        raise KeyboardInterrupt

    rig.run_hook = interrupt
    with pytest.raises(KeyboardInterrupt):
        rig.launch()

    assert rig.nothing_serving() == [] and rig.teardown_seen() is not None
    assert "frozen-engine" not in rig.store.records and rig.rows() == []


def test_teardown_stops_the_services_but_keeps_the_elasticsearch_data(tmp_path):
    """A1: after the run the copy is still there, for the next run or the label; the proxy is down."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("drop")
    rig.launch()

    assert rig.cluster.state() == rig.teardown_seen()["cluster"] == expected_copy("drop")
    assert rig.proxy().state != "running" and rig.nothing_serving() == []
    assert rig.docker.of_kind("service-stop")[-1]["j"] > rig.journal.last("run")


def test_a_second_launch_is_refused_while_the_engine_lock_is_held_and_touches_nothing(tmp_path):
    """O10: a held frozen-engine lock stops the launch before any cluster request; the holder's
    record survives."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    rig.store.records["frozen-engine"] = "someone-else"
    rig.launch_module
    with pytest.raises(Exception) as caught:
        rig.launch()

    assert not isinstance(caught.value, (AttributeError, TypeError, NameError))
    _no_lab_traffic(rig)
    assert rig.rows() == []
    assert rig.store.records["frozen-engine"] == "someone-else"


# -- reference mode (O8) -----------------------------------------------------------------------------------


def test_a_reference_launch_serves_an_unconfirmed_case_and_writes_no_row(tmp_path):
    """O8/O9: the labelling run happens before `confirmed` is filled; it serves the copy like any
    run, announces its id, appends nothing, and frees the lock."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("drift", confirmed=False)

    assert rig.launch(reference=True) == RUN_ID

    assert "run" in rig.journal.ops() and not rig.index.exists()
    assert instant(_opt(rig.argv, "--as-of")) == instant(T)
    assert rig.cluster.state() == expected_copy("drift") and "frozen-engine" not in rig.store.records


def test_a_launch_handed_the_lock_token_joins_it_and_leaves_it_held(tmp_path):
    """A1: make-a-case holds the engine lock through labelling; its reference run is launched with
    the token, does not take or release the lock."""
    from chaos import lock

    rig = LabRig(tmp_path)
    rig.write_expected_case("none", confirmed=False)
    token = lock.take(rig.store, lock.FROZEN_ENGINE)
    record, before = rig.store.records["frozen-engine"], len(rig.journal)

    rig.launch(reference=True, lock_token=token)

    assert rig.store.records["frozen-engine"] == record and rig.lock_in_run
    assert "lock.create" not in rig.journal.ops()[before:]


def test_a_launch_handed_a_token_that_is_not_the_holders_is_refused_and_leaves_the_lock_held(tmp_path):
    """A1/O10: a wrong token stops the launch before any cluster request; the holder keeps the lock."""
    from chaos import lock

    rig = LabRig(tmp_path)
    rig.write_expected_case("none", confirmed=False)
    lock.take(rig.store, lock.FROZEN_ENGINE)
    record = rig.store.records["frozen-engine"]
    rig.launch_module

    with pytest.raises(Exception) as caught:
        rig.launch(reference=True, lock_token="not-the-holders-token")

    assert not isinstance(caught.value, (AttributeError, TypeError, NameError, ImportError, OSError))
    _no_lab_traffic(rig)
    assert rig.rows() == [] and rig.lock_in_run is None
    assert rig.store.records["frozen-engine"] == record
    _only_lock_traffic(rig.journal, "wrong token")


# =====================================================================================================
# r6.4.2 repairs (attack batch 1): one test per family, whose input is the whole class
# =====================================================================================================


def _only_lock_traffic(journal, where):
    """A refused launch made no ops call, cluster request or run: the journal holds lock and clock entries only."""
    other = [(op, d) for op, d in journal if not op.startswith(("lock.", "clock."))]
    assert not other, (where, other)


def _launch_cases(tmp_path, joined):
    """A rig whose launch is scored (owned lock) or a reference run joined to make-a-case's token."""
    from chaos import lock

    def build(journal=None):
        rig = LabRig(tmp_path / f"r{len(list(tmp_path.glob('r*')))}", journal=journal)
        rig.write_expected_case("drift", confirmed=not joined)
        return rig, (lock.take(rig.store, lock.FROZEN_ENGINE) if joined else None)

    return build


def _teardown_ran_under_the_lock(rig, joined, where):
    """Nothing the launch started still serves, and when it had started a service, the engine lock record still
    existed when the last one stopped (the teardown), owned or joined: an owned lock is released after
    teardown, never before it (C3/O9). (r6.4.3 C-rig: a teardown is what it does at the docker edge.)"""
    assert rig.nothing_serving() == [], (where, rig.nothing_serving())
    if rig.docker.of_kind("stub-start") or rig.docker.of_kind("proxy-start") or rig.docker.of_kind("service-stop"):
        seen = rig.teardown_seen()
        assert seen is not None and "frozen-engine" in seen["locks"], (where, seen and seen["locks"])


def test_a_launch_cut_at_any_step_after_verify_tears_down_once_and_frees_only_a_lock_it_took(tmp_path):
    """C3/A1/O9/O10: for every step after the UUID check (cluster request, lab op, agent run) and the row
    write, owned or joined lock: torn down under the lock (nothing it started still serves); an owned lock is
    released once, after the launch's last docker call; a joined one is untouched. A step is a docker call, a
    cluster request or the agent run, up to the run (the teardown's own calls are not cut)."""
    for joined in (False, True):
        build = _launch_cases(tmp_path / ("joined" if joined else "owned"), joined)
        clean = FaultJournal()
        rig, token = build(clean)
        rig.launch(**({"reference": True, "lock_token": token} if joined else {}))
        # the step at which the cluster served the snapshot's UUID: the fake has no other route that does
        assert rig.cluster.uuid_served_step is not None, "the launch never read the snapshot to check its UUID"
        run_step = [op for op, _d in clean.step_log].index("run") + 1
        steps = list(range(rig.cluster.uuid_served_step + 1, run_step + 1))
        assert len(steps) >= 10, "the clean run shows too few steps to be cut anywhere"
        _teardown_ran_under_the_lock(rig, joined, "uncut, " + ("joined" if joined else "owned"))

        for n in steps + ["row"]:
            if n == "row" and joined:
                continue                                     # a reference run writes no row
            journal = FaultJournal(trip_at=None if n == "row" else n)
            rig, token = build(journal)
            if n == "row":
                rig.index.mkdir()                            # the row cannot be written: a directory is in its place
            record = dict(rig.store.records)
            started = len(journal)
            where = f"{'joined' if joined else 'owned'}, cut at {n}: {clean.step_log[n - 1] if n != 'row' else 'the row write'}"
            caught = None
            try:
                rig.launch(**({"reference": True, "lock_token": token} if joined else {}))
            except Exception as exc:  # noqa: BLE001 - every failure is the class under test
                caught = exc
            ops = journal.ops()

            assert not isinstance(caught, _NOT_A_REFUSAL + (AssertionError, NotImplementedError)), (where, repr(caught))
            if n == "row" or (clean.step_log[n - 1][0] != "run"):
                assert caught is not None, f"{where}: the launch went on as if nothing failed"
            _teardown_ran_under_the_lock(rig, joined, where)
            if joined:
                assert rig.store.records == record and "lock.delete" not in ops[started:], where
                assert "lock.create" not in ops[started:], where
            else:
                assert ops.count("lock.delete") == 1 and rig.journal.last("lock.delete") > max(rig.docker_at()), where
                assert "frozen-engine" not in rig.store.records, where
            if n != "row":
                assert rig.rows() == [], where


@pytest.mark.parametrize("how", ["holder-cleared", "never-held"])
def test_a_token_handed_to_a_launch_while_no_one_holds_the_lock_is_refused_before_anything(tmp_path, how):
    """C3/O10: a token whose lock is free (its holder cleared, or never issued) does not take the lock
    or reach the cluster, the lab or the agent."""
    from chaos import lock

    rig = LabRig(tmp_path)
    rig.write_expected_case("none", confirmed=False)
    token = "0123456789abcdef" * 2
    if how == "holder-cleared":
        token = lock.take(rig.store, lock.FROZEN_ENGINE)
        lock.clear(rig.store, lock.FROZEN_ENGINE)
    rig.launch_module
    before = len(rig.journal)

    with pytest.raises(Exception) as caught:
        rig.launch(reference=True, lock_token=token)

    assert not isinstance(caught.value, _NOT_A_REFUSAL + (OSError,)), repr(caught.value)
    _no_lab_traffic(rig)
    assert "run" not in rig.journal.ops() and rig.rows() == [] and not rig.store.records
    assert "lock.create" not in rig.journal.ops()[before:]
    _only_lock_traffic(rig.journal, "refused")


# -- C4: a copy left by an earlier launch is never trusted beyond what a restore would give ---------------


def _sites(value):
    """Every way a scalar can be nudged, as `(site, candidates)`: the value as a whole, and each number and
    each quoted string inside a string (a Painless condition holds a threshold and a salt)."""
    if isinstance(value, bool):
        yield "", [not value]
    elif isinstance(value, (int, float)):
        yield "", [value + 1, value - 1, value + 35]
    elif isinstance(value, str):
        yield "", [value + "_x"]
        for k, m in enumerate(re.finditer(r"\d+", value)):
            n = int(m.group())
            yield f"#num{k}", [value[:m.start()] + str(c) + value[m.end():] for c in (n + 1, n - 1, n + 35) if c >= 0]
        for k, m in enumerate(re.finditer(r"'([^']*)'", value)):
            yield f"#quoted{k}", [value[:m.start(1)] + c + value[m.end(1):] for c in (m.group(1) + "a", "a")]


def _leaves(node, path=()):
    if isinstance(node, dict):
        for key, child in node.items():
            yield from _leaves(child, path + (key,))
    elif isinstance(node, list):
        for i, child in enumerate(node):
            yield from _leaves(child, path + (i,))
    else:
        yield path, node


def _set(node, path, value):
    node = copy.deepcopy(node)
    here = node
    for step in path[:-1]:
        here = here[step]
    here[path[-1]] = value
    return node


def _later(span_start, delta):
    return (instant(span_start) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def _expected_or_none(mutation, span_start):
    try:
        return expected_variant(mutation, span_start)
    except Exception:  # noqa: BLE001 - a nudge the oracle cannot evaluate (e.g. a mangled condition) is not a variant
        return None


def _perturbations(base_name, mutation):
    """One variant per scalar leaf of the resolved mutation (and of span_start) whose nudge changes the
    expected end state; a leaf no nudge of which changes it (`stream`, `pipeline`, `ignore_failure`) is not a variant."""
    base = expected_variant(mutation, SPAN_START)
    found = {}
    for path, value in [*_leaves(mutation), (("span_start",), SPAN_START)]:
        if path in (("kind",),):
            continue     # not a value of the overlay but which overlay it is
        if path == ("dataset",) and mutation.get("kind") == "schema-drift":
            continue     # the resolver pins schema-drift's dataset to the auth dataset (_resolve_schema_drift)
        for site, candidates in _sites(value) if path != ("span_start",) else [
                ("", [_later(SPAN_START, timedelta(seconds=d)) for d in (1, -1, 60, -60, 3600, 7200)])]:
            for candidate in candidates:
                other = (_set(mutation, path, candidate), SPAN_START) if path != ("span_start",) else (mutation, candidate)
                if path == ("dataset",) and isinstance(candidate, str):
                    # The resolver derives a dataset's stream and pipeline (chaos.mutations): never one alone.
                    other = ({**other[0], "stream": f"logs-{candidate}-*", "pipeline": f"logs-{candidate}@custom"},
                             SPAN_START)
                if mutation.get("kind") == "schema-drift" and path in (("processor", "rename", "field"),
                                                                       ("processor", "rename", "target_field")):
                    # The resolver sets `fields = [from, to]` from the rename: never one alone.
                    rename = other[0]["processor"]["rename"]
                    other = ({**other[0], "fields": [rename["field"], rename["target_field"]]}, other[1])
                state = _expected_or_none(*other)
                if state is not None and state != base:
                    found[f"{base_name}/{'.'.join(map(str, path))}{site}"] = other
                    break
    return found


_DROP_VARIANTS = _perturbations("drop", DATA_DROP)
_DRIFT_VARIANTS = _perturbations("drift", SCHEMA_DRIFT)
VARIANTS = {"none": (None, SPAN_START), "drop": (DATA_DROP, SPAN_START), "drift": (SCHEMA_DRIFT, SPAN_START),
            **_DROP_VARIANTS, **_DRIFT_VARIANTS}
PAIRS = [("none", "drop")] + [(a, b) for name in _DROP_VARIANTS for a, b in (("drop", name), (name, "drop"))] + [
    (a, b) for name in _DRIFT_VARIANTS for a, b in (("drift", name), (name, "drift"))]


def test_the_walk_over_every_leaf_reaches_the_leaves_the_oracle_distinguishes():
    """C4: the generated variants cover the threshold, the salt, the rename target and span_start (and the
    dataset of data-drop, field and rename source, which also change the copy), so the walk cannot go vacuous."""
    for needle in ("drop/processor.drop.if#num", "drop/processor.drop.if#quoted", "drop/span_start", "drop/dataset"):
        assert any(name.startswith(needle) for name in _DROP_VARIANTS), (needle, sorted(_DROP_VARIANTS))
    for needle in ("drift/processor.rename.target_field", "drift/span_start"):
        assert any(name.startswith(needle) for name in _DRIFT_VARIANTS), (needle, sorted(_DRIFT_VARIANTS))


@pytest.mark.parametrize("uuid_ok", [True, False], ids=["uuid-ok", "uuid-changed"])
@pytest.mark.parametrize("prior", ["empty", "same", "neighbour", "dirty"])
@pytest.mark.parametrize("target, other", PAIRS, ids=[f"{a}<-{b}" for a, b in PAIRS])
def test_a_launch_after_any_earlier_copy_ends_as_it_would_from_an_empty_cluster(tmp_path, target, other, prior, uuid_ok):
    """C4/O6/A4: whatever copy an earlier launch left (same variant, one leaf different, half-made), the
    launch is refused on a changed snapshot UUID, else leaves the variant's own end state and a valid row."""
    assert expected_variant(*VARIANTS[target]) != expected_variant(*VARIANTS[other]), "the leaf must change the copy"
    rig = LabRig(tmp_path, fail=_once(lambda m, p, b: p.endswith("/_delete_by_query")) if prior == "dirty" else None)
    if prior != "empty":
        rig.write_variant_case(*VARIANTS[target if prior == "same" else other])
        if prior == "dirty":
            with pytest.raises(Exception):
                rig.launch()
            assert not is_clean_marker(rig.marker()), rig.marker()
        else:
            rig.launch()
    rig.write_variant_case(*VARIANTS[target])
    if not uuid_ok:
        rig.cluster.snapshot_uuid = "another-uuid"
    seen = (len(rig.cluster.mutations), rig.journal.ops().count("run"), len(rig.rows()))
    rig.launch_module

    if uuid_ok:
        rig.launch()
        assert [r["verdict"] for r in rig.rows()][seen[2]:] == ["valid"], rig.rows()
        assert rig.cluster.state() == expected_variant(*VARIANTS[target]) and rig.cluster.pipelines == {}
        return
    with pytest.raises(Exception, match="(?i)uuid"):
        rig.launch()
    assert (len(rig.cluster.mutations), rig.journal.ops().count("run"), len(rig.rows())) == seen
    assert "frozen-engine" not in rig.store.records


# -- C5 retired: the clock offset taken at a node restart is withdrawn by D15 revised (r6.4.3); its
# successor is the D15 section at the end of this file.


# -- C6: every recorded fact is compared at launch, each on its own ----------------------------------------

INDICES = [AUTH, SYSLOG, NGINX, ALERTS]


def _write_case_differing_in(rig, fact):
    """case.yaml/alert.json for the `drop` variant, with exactly one recorded fact off (or the copy's
    own alert in the snapshot off, for `copy-alert`)."""
    state = expected_copy("drop")
    original = state[ALERTS]["id-young"][1]
    if fact == "copy-alert":
        changed = {**original, "host.name": "web-2"}
        rig.cluster.content[ALERTS]["id-young"]["_source"]["host.name"] = "web-2"
        state[ALERTS]["id-young"] = (state[ALERTS]["id-young"][0], changed)
        return rig.write_variant_case(DATA_DROP, state=state, alert_json=original, alert=canonical_digest(original))
    case = rig.write_variant_case(DATA_DROP, alert_json={**original, "host.name": "web-9"} if fact == "alert-json" else None)
    over = {"case-alert": {"alert": "e" * 64}, "content": {"content": "f" * 64}}.get(fact)
    if fact.startswith("count:"):
        index = fact.split(":", 1)[1]
        over = {"counts": {**case["counts"], index: case["counts"][index] + 1}}
    if fact == "unrecorded-index":      # the copy holds an index the case recorded no count for
        over = {"counts": {k: v for k, v in case["counts"].items() if k != NGINX}}
    if fact == "phantom-index":         # the case recorded a count for an index the copy does not hold
        over = {"counts": {**case["counts"], "logs-ghost-default-2026.10.01-000001": 3}}
    if over:
        rig.write_variant_case(DATA_DROP, **over)
    return case


@pytest.mark.parametrize("fact, needle", [
    ("content", "content"), ("case-alert", "alert"), ("alert-json", "alert"), ("copy-alert", "alert"),
    *[(f"count:{i}", i) for i in INDICES], ("unrecorded-index", NGINX), ("phantom-index", "ghost")])
def test_a_copy_differing_from_the_case_in_exactly_one_recorded_fact_is_stale_and_names_it(tmp_path, fact, needle):
    """C6/A1/A2/P2: one count (or an index missing from either side), the content digest, case.yaml's alert,
    alert.json or the copy's alert off, all else right: stale, run, bound row, reason names the fact."""
    rig = LabRig(tmp_path)
    _write_case_differing_in(rig, fact)
    rig.launch()

    [row] = rig.rows()
    assert (row["verdict"], row["run_id"], row["binding"]) == ("stale", RUN_ID, rig.binding())
    assert needle in row["reason"], row


# -- D23: a stale verdict is not trusted by the next launch -------------------------------------------------


@pytest.mark.parametrize("fact", ["content", "case-alert", "count:" + SYSLOG])
def test_a_stale_launch_marks_the_copy_dirty_and_the_next_launch_restores_it_whole(tmp_path, fact):
    """D23/A4: after a valid launch the marker is clean; a stale verdict makes it dirty; the next
    launch restores the whole snapshot and is valid."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("drop")
    rig.launch()
    assert is_clean_marker(rig.marker()) and rig.cluster.restores == 1
    _write_case_differing_in(rig, fact)
    rig.launch()
    assert [r["verdict"] for r in rig.rows()] == ["valid", "stale"]
    assert not is_clean_marker(rig.marker()), rig.marker()

    rig.write_expected_case("drop")
    rig.launch()

    assert rig.cluster.restores == 2 and rig.cluster.state() == expected_copy("drop")
    assert [r["verdict"] for r in rig.rows()] == ["valid", "stale", "valid"]


# -- B1: the node is up before the cluster is asked anything ---------------------------------------------


@pytest.mark.parametrize("start", ["cold", "after-a-launch-same-variant", "after-a-launch-other-variant",
                                   "make-a-case-after-a-launch"])
def test_a_launch_finds_the_node_stopped_and_starts_it_before_asking_it_anything(tmp_path, start):
    """B1/A1: teardown stops the node (and a node may never have run): a launch, or make-a-case and its
    reference run, make sure it is up before the first cluster request and end valid in the variant's state."""
    rig = LabRig(tmp_path)          # a cold lab: no engine, no node
    rig.write_expected_case("drop")
    if start != "cold":
        rig.launch()
        if rig.node_running():      # a teardown that leaves the node up does not exercise the claim: stop it
            rig.docker.containers[(rig.docker.node().scope, rig.docker.node().name)].state = "exited"
    if start == "make-a-case-after-a-launch":
        with rig.write_case("young", None) as held:
            assert rig.launch(reference=True, lock_token=held.token) == RUN_ID
        assert rig.cluster.down_requests == [] and rig.cluster.state() == expected_copy("none")
        return
    if start.endswith("other-variant"):
        rig.write_expected_case("drift")
    kind = "drift" if start.endswith("other-variant") else "drop"
    mark = len(rig.journal)

    rig.launch()

    assert rig.cluster.down_requests == [], "the cluster was asked something while its node was stopped"
    assert any(e["j"] >= mark for e in rig.docker.of_kind("node-start")), "no frozen node was started"
    assert [r["verdict"] for r in rig.rows()][-1] == "valid" and rig.cluster.state() == expected_copy(kind)


# -- D24: the freeze owns the patterns ----------------------------------------------------------------------

ALERTS_ALT = ".internal.alerts-security.alerts-*"     # matches the same index as the old built-in default


def test_a_launch_works_on_the_patterns_of_its_freeze_not_on_a_built_in_default(tmp_path):
    """D24/O2a: a freeze whose alerts pattern is spelled another way from any default is launched valid
    and no request to the cluster carries the default spelling."""
    rig = LabRig(tmp_path, patterns=(EVENTS, ALERTS_ALT))
    rig.write_expected_case("drop")
    rig.launch()

    assert [r["verdict"] for r in rig.rows()] == ["valid"] and rig.cluster.state() == expected_copy("drop")
    asked_for = [p for _m, p, _b in rig.cluster.requests if ALERTS_ALT in p]
    assert asked_for, "no request to the cluster used the freeze's alerts pattern"
    asked = json.dumps([[m, p, b] for m, p, b in rig.cluster.requests], default=str)
    assert ALERTS_PATTERN not in asked


@pytest.mark.parametrize("now_configured", [
    ("logs-*,extra-*", ALERTS_ALT), ("logs-other-*", ALERTS_ALT), (EVENTS, ".internal.alerts-other-*"),
    ("logs-other-*", ".internal.alerts-other-*")], ids=["events-widened", "events-changed", "alerts-changed", "both-changed"])
def test_a_launch_is_refused_before_anything_when_the_tenants_patterns_are_no_longer_the_freezes(tmp_path, now_configured):
    """D24/A2: the lab tenant now configures other patterns than the freeze recorded: no cluster request,
    no lab op, no run, no row, engine free; with the settings restored the same case launches valid."""
    rig = LabRig(tmp_path, patterns=(EVENTS, ALERTS_ALT))
    rig.write_expected_case("none")
    rig.set_tenant_patterns(*now_configured)
    rig.launch_module

    with pytest.raises(Exception) as caught:
        rig.launch()

    assert not isinstance(caught.value, _NOT_A_REFUSAL), repr(caught.value)
    _no_lab_traffic(rig)
    assert "run" not in rig.journal.ops() and rig.rows() == [] and "frozen-engine" not in rig.store.records
    rig.set_tenant_patterns(EVENTS, ALERTS_ALT)
    rig.launch()
    assert [r["verdict"] for r in rig.rows()] == ["valid"]


def test_no_lab_script_carries_a_built_in_pattern_default_or_a_pattern_flag():
    """D24: the freeze owns the patterns; no lab script holds an events/alerts pattern literal or a `--pattern` flag."""
    scripts = [LAUNCH.parent / name for name in ("launch_frozen.py", "make_case.py", "capture_case.py", "lab_ops.py")]
    found = []
    for path in scripts:
        tree = ast.parse(path.read_text())
        docs = {id(n.body[0].value) for n in ast.walk(tree) if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef))
                and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
        found += [(path.name, n.value) for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                  and id(n) not in docs and (n.value == "--pattern" or "alerts-default" in n.value or n.value in ("logs-*", EVENTS))]
    assert not found, found


# =====================================================================================================
# r6.4.3 (finalize-stage review of PR #1461): D25, D15 revised, findings 2 and 4
# =====================================================================================================

LIFECYCLE = ("run", "create", "start", "restart", "stop", "kill", "rm")


def _node_names(rig):
    return {e["container"].name for e in rig.docker.of_kind("node-start")}


def _restores(rig):
    return [e for e in rig.docker.of_kind("curl") if e["path"].split("?")[0].endswith("/_restore")]


def _assert_every_restore_went_into_a_fresh_node(rig, where=""):
    """D25: before each restore, every node that served the cluster earlier was removed and its data volume
    discarded; the restoring node and its data volume never served before; the cluster it restores into holds
    no index; the restore is the whole snapshot. Nothing was ever closed, and no index of the freeze was
    deleted, to make room."""
    curls, removed = rig.docker.of_kind("curl"), rig.docker.of_kind("container-rm")
    wiped = rig.docker.of_kind("volume-rm")
    restores = _restores(rig)
    assert restores, f"{where}: no restore happened"
    for r in restores:
        earlier = [e for e in curls if e["j"] < r["j"] and e["node"] != r["node"]]
        for e in earlier:
            assert any(x["container"].id == e["node"] and x["j"] < r["j"] for x in removed), (
                where, "the old node container was not removed before the restore", e["path"])
            assert e["data"] != r["data"], (where, "the restore went into a data volume an older node used")
            if e["data"][0] == "vol":
                assert any(w["volume"] == e["data"] and w["j"] < r["j"] for w in wiped), (
                    where, "the old node's data volume was not discarded before the restore", e["data"])
        assert not any(e["data"] == r["data"] for e in curls if e["j"] < r["j"] and e["node"] != r["node"])
    for entry in [m for m in rig.cluster.mutations if m["kind"] == "restore"]:
        assert entry["indices_before"] == [], (where, "restored over existing indices", entry["indices_before"])
        assert entry["whole"], (where, "a partial restore", entry["target"])
    names = set(rig.freeze["elastic"]["indices"])
    assert not [p for m, p, _b in rig.cluster.requests if "/_close" in p], where
    deleted = [p for m, p, _b in rig.cluster.requests if m == "DELETE"
               and set(p.strip("/").split("?")[0].split("/")[0].split(",")) & names]
    assert not deleted, (where, deleted)
    assert all(w["volume"][2] != "lab-engine-state" for w in wiped), "the engine's state volume was wiped"
    for w in wiped:      # the marker is not on the node's volume: at each wipe a marker that is not clean is kept
        assert not is_clean_marker(w["seen"]), (where, "a clean marker stood while the copy was wiped", w["seen"])


@pytest.mark.parametrize("before", ["cold", "variant-switch", "dirty-marker", "no-marker", "stale"])
def test_every_restore_goes_into_a_fresh_node_and_the_copy_ends_valid(tmp_path, before):
    """D25: whatever an earlier launch left (another variant, a half-made copy, no marker, a stale verdict),
    a launch that restores discards the old node container and its data volume, starts a new node, restores
    the whole snapshot into it, sends no `_close` or index DELETE to make room, and ends valid."""
    rig = LabRig(tmp_path, fail=_once(lambda m, p, b: p.endswith("/_delete_by_query")) if before == "dirty-marker" else None)
    if before == "variant-switch":
        rig.write_expected_case("drift")
        rig.launch()
    elif before == "dirty-marker":
        rig.write_expected_case("drop")
        with pytest.raises(Exception):
            rig.launch()
    elif before == "no-marker":
        rig.write_expected_case("drop")
        rig.launch()
        rig.drop_marker()
    elif before == "stale":
        rig.write_expected_case("drop", content="f" * 64)
        rig.launch()
    rig.write_expected_case("drop")
    rows = len(rig.rows())
    rig.launch()

    assert [r["verdict"] for r in rig.rows()][rows:] == ["valid"], rig.rows()
    assert rig.cluster.state() == expected_copy("drop") and is_clean_marker(rig.marker())
    _assert_every_restore_went_into_a_fresh_node(rig, before)


def test_a_launch_with_a_clean_marker_for_its_variant_reuses_the_copy_and_wipes_nothing(tmp_path):
    """D25: a clean marker for the launch's own variant: no restore, no node or volume discarded, the same
    data volume serves both launches, both valid."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("drift")
    rig.launch()
    wiped, restores = len(rig.docker.of_kind("volume-rm")), rig.cluster.restores
    first_data = {e["data"] for e in rig.docker.of_kind("curl")}
    mark = len(rig.journal)
    rig.launch()

    assert rig.cluster.restores == restores and len(rig.docker.of_kind("volume-rm")) == wiped
    assert {e["data"] for e in rig.docker.of_kind("curl") if e["j"] >= mark} <= first_data
    assert [r["verdict"] for r in rig.rows()] == ["valid", "valid"]


# -- D15 revised: the node's clock offset is written when the agent starts ------------------------------


def _offset_writes(rig):
    """`(journal index, clock reading, offset)` of each write to a file a frozen node's `V2_CLOCK_OFFSET_FILE`
    names, in order."""
    files = set()
    for e in rig.docker.of_kind("node-start"):
        if e["offset_file"]:
            store, key, _ro = rig.docker.resolve(e["container"], e["offset_file"])
            files.add((store, key))
    out = []
    for w in rig.docker.writes:
        if (w["store"], w["key"]) in files and w["data"].strip():
            out.append((w["j"], w["clock"], int(w["data"].decode().strip()), w["inode"]))
    return out


OFFSET_RECORD = 24
_RECORD = re.compile(rb" *[-+]?[0-9]+ *\n")


def _assert_the_offset_file_is_a_fixed_record_rewritten_in_place(rig, where=""):
    """r6.4.3 settlements: every write to a file a frozen node's `V2_CLOCK_OFFSET_FILE` names is the whole
    24-byte record (signed decimal, space-padded, newline-ended) written at byte 0 and leaving the file 24 bytes;
    the file is created at that size (by any means, a rename into place included) before the node that maps it
    starts; once there it is only written in place (never truncated), and every write while a node maps it
    reaches that node's file (the same inode: no replacement either)."""
    starts = rig.docker.of_kind("node-start")
    assert starts, f"{where}: no frozen node was started"
    by_file: dict = {}
    for e in starts:
        assert e["offset_file"], (where, "the node runs without an offset file")
        store, key, _ro = rig.docker.resolve(e["container"], e["offset_file"])
        by_file.setdefault((store, key), []).append(e)
    for where_file, nodes in by_file.items():
        writes = [w for w in rig.docker.writes if (w["store"], w["key"]) == where_file]
        assert writes, (where, "the offset file was never written")
        seen_inodes: set = set()
        for w in writes:
            creates = w["inode"] not in seen_inodes      # this write brings a new file to the path (any way of making it)
            seen_inodes.add(w["inode"])
            assert creates or w["mode"] == "in-place", (where, f"the offset file was rewritten with mode {w['mode']!r}: "
                                                         "a truncate, not an in-place rewrite", w["data"])
            assert len(w["data"]) == OFFSET_RECORD and _RECORD.fullmatch(w["data"]), (
                where, "a write is not the whole 24-byte record at byte 0", w["data"])
            assert w["size"] == OFFSET_RECORD, (where, "the offset file is not 24 bytes after a write", w["size"])
        for k, e in enumerate(nodes):
            created = [w for w in writes if w["inode"] == e["inode"]]
            assert e["inode"] is not None and created and created[0]["j"] < e["j"], (
                where, "the node started before its offset file was created at its size")
            assert e["offset"] is not None and len(e["offset"].encode()) == OFFSET_RECORD, (where, e["offset"])
            until = nodes[k + 1]["j"] if k + 1 < len(nodes) else len(rig.journal)
            later = [w for w in writes if e["j"] < w["j"] < until]
            assert all(w["inode"] == e["inode"] for w in later), (
                where, "while the node maps its offset file, a write reached another file at that path")


@pytest.mark.parametrize("before", ["cold", "same-variant", "other-variant"])
def test_the_offset_file_is_a_fixed_24_byte_record_created_before_the_node_and_only_rewritten_in_place(tmp_path, before):
    """r6.4.3 settlements/D15 revised: the node's offset file is one 24-byte record, created at that size before
    the node starts and from then on rewritten in place at byte 0, never truncated or replaced, across the
    launches that reuse a copy or replace it."""
    rig = LabRig(tmp_path)
    if before != "cold":
        rig.write_expected_case("drop")
        rig.launch()
    rig.write_expected_case("drift" if before == "other-variant" else "drop")
    rig.launch()

    _assert_the_offset_file_is_a_fixed_record_rewritten_in_place(rig, before)


def _assert_every_node_start_already_holds_the_offset_for_T(rig, where=""):
    starts = rig.docker.of_kind("node-start")
    assert starts, f"{where}: no frozen node was started"
    for e in starts:
        env = e["container"].env
        assert "LD_PRELOAD" in env and e["offset_file"], (where, "the node runs without the file-fed shim", env)
        assert e["offset"] is not None and e["offset"].strip(), (where, "the node started before its offset file held T", e["offset"])
        node_now = e["clock"] + timedelta(seconds=int(e["offset"].strip()))
        assert abs((node_now - instant(T)).total_seconds()) <= 5, (where, "at its start the node's clock is not T", e["offset"])


@pytest.mark.parametrize("before", ["cold", "same-variant", "other-variant"])
def test_every_frozen_node_starts_with_its_offset_file_already_holding_T_minus_now(tmp_path, before):
    """D15 revised/P1: no process in the copy ever reads the real now: each time a frozen node starts, the
    shim is preloaded and the file its `V2_CLOCK_OFFSET_FILE` names already holds the offset that makes the
    node's wall clock read T at that moment."""
    rig = LabRig(tmp_path)
    if before != "cold":
        rig.write_expected_case("drop")
        rig.launch()
    rig.write_expected_case("drift" if before == "other-variant" else "drop")
    rig.launch()

    _assert_every_node_start_already_holds_the_offset_for_T(rig, before)


def test_the_offset_is_rewritten_to_T_minus_now_as_the_last_lab_step_and_the_node_clock_matches_the_agents(tmp_path):
    """D15 revised/O5: with a slow setup (a six-minute restore, minutes of overlays, slow searches), the last
    lab step before the agent runs is the rewrite of the offset file to T - now, read on the clock at the
    rewrite; no docker call or cluster request comes between it and the run. From the run on, the node's
    clock (now + offset) and the agent's (`--as-of T` from its start) agree within one clock step. An offset
    fixed at a node restart before the health wait, the user, the counts and the proxy fails this."""
    step = 1
    rig = LabRig(tmp_path, clock_step=step, latency={
        "restore": timedelta(minutes=6), "delete_by_query": timedelta(seconds=90),
        "reindex": timedelta(minutes=2), "search": timedelta(seconds=5)})
    rig.write_expected_case("drift")
    rig.launch()
    run_j = rig.journal.first("run")

    writes = [w for w in _offset_writes(rig) if w[0] < run_j]
    assert writes, "the offset file was never written before the run"
    j, at, offset, inode = writes[-1]
    serving = [e for e in rig.docker.of_kind("node-start") if e["j"] < run_j][-1]
    assert inode == serving["inode"], ("the offset was not rewritten in place: the running node's shim maps the "
                                       "file it found at its start, and a new file put in its place is never read")
    assert abs((at + timedelta(seconds=offset) - instant(T)).total_seconds()) <= step, (at, offset)
    between = [(op, d) for op, d in rig.journal[j + 1:run_j] if op in ("docker", "es")]
    assert not between, f"lab steps after the offset rewrite and before the run: {between[:5]}"
    assert (rig.run_clock - at).total_seconds() <= step, (rig.run_clock, at)
    node_at_run = rig.run_clock + timedelta(seconds=offset)
    assert abs((node_at_run - instant(T)).total_seconds()) <= step, node_at_run
    assert instant(_opt(rig.argv, "--as-of")) == instant(T)
    proxy, counts = rig.docker.of_kind("proxy-start")[-1]["j"], rig.es_at(lambda m, p: p.endswith("/_count"))
    assert proxy < j and max(counts) < j, "the rewrite comes after the proxy start and the count comparison"


def test_a_launch_never_restarts_the_frozen_node_for_its_clock(tmp_path):
    """D15 revised: once the copy is ready (after the last overlay, or, on a clean marker, after the first
    request the node serves), no launch stops, starts, restarts or replaces the frozen node before its run."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("drop")
    for n in range(2):
        mark = len(rig.journal)
        rig.launch()
        run_j = rig.journal.last("run")
        es = [i for i, (op, _d) in enumerate(rig.journal) if op == "es" and i >= mark]
        mutating = [i for i in es if rig.journal[i][1][1].endswith(("/_delete_by_query", "/_reindex", "/_restore"))]
        ready = max(mutating) if mutating else min(es)
        names = _node_names(rig)
        touched = [(i, d) for i, (op, d) in enumerate(rig.journal)
                   if op == "docker" and ready < i < run_j and "/" in d[0] and d[1] in LIFECYCLE and d[2] in names]
        assert not touched, (f"launch {n + 1}", touched)
    assert [r["verdict"] for r in rig.rows()] == ["valid", "valid"]


# -- finding 2: a node that is not listening yet is waited for --------------------------------------------


@pytest.mark.parametrize("kind", ["none", "drift"])
def test_a_node_that_is_not_listening_yet_is_waited_for_and_the_launch_proceeds(tmp_path, kind):
    """r6.4.3 finding 2/O6: a freshly started node refuses connections for a while (curl exits 7, `000`);
    the launch waits through it and ends valid, it does not fail."""
    rig = LabRig(tmp_path, boot_requests=3)
    rig.write_expected_case(kind)
    rig.launch()

    assert rig.docker.of_kind("curl-refused"), "the node never refused a connection: the claim was not exercised"
    assert [r["verdict"] for r in rig.rows()] == ["valid"] and rig.cluster.state() == expected_copy(kind)


# -- finding 4: a stopped engine is started again ---------------------------------------------------------


def test_an_engine_that_exists_but_is_stopped_is_started_again_not_assumed_up(tmp_path):
    """r6.4.3 finding 4: after a reboot (or a `docker stop`) the engine container exists but does not run
    (`inspect` says `false` with rc 0); the next launch brings it up and ends valid."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    rig.launch()
    [engine] = [c for c in rig.docker.containers.values() if c.engine]
    rig.docker.stop_engine(engine.scope, engine.name)
    rig.launch()

    assert [r["verdict"] for r in rig.rows()] == ["valid", "valid"]
    assert any(c.engine and c.state == "running" for c in rig.docker.containers.values())
