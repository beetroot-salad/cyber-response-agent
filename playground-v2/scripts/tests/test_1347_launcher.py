"""#1347 r6.4.1 A1-A7: the launcher readies a variant's frozen copy, runs the agent on it and writes the row.

Entry point bound by this contract: `playground-v2/scripts/launch_frozen.py::launch(case_dir, *,
freezes_dir, patterns, index, parts_dir, lock_store, es, ops, run_fn, clock, env, tenant,
knowledge=None, reference=False, lock_token=None) -> run_id`.

* `es` is the FROZEN cluster through the chaos seam's `es_request(method, path, body=None)`; the
  launcher talks to it directly, never through the frozen proxy.
* `ops` (see `_lab_fakes.LabOps`): read_marker, write_marker, load_stubs(parts_dir, as_of,
  mutations), restart_node(clock_offset), start_proxy() -> the frozen proxy's own url,
  content_digest(), teardown().
* `case_dir` holds alert.json, ground_truth.yaml and case.yaml (freeze, alert, age, overlay
  `None | {mutations, span_start}`, counts, content, confirmed); the freeze is
  `freezes_dir/<freeze>/freeze.yaml`; parts are `parts_dir/<freeze>/<name>`, digests bare hex.
* `lock_token`: a token already holding the frozen-engine lock (make-a-case's); the launch joins it
  and does not release it.
* The row's `binding` comes from the scorer: `evaluations.held_out.binding(freeze_doc, case_doc)`
  over the parsed freeze.yaml and case.yaml, imported, not re-implemented (A8).

Tests read the copy's END STATE from `_lab_fakes.FakeCluster`, not a request sequence (A3).
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
import yaml
from _lab_fakes import (AUTH, AUTH_AFTER_T, AUTH_IN_SPAN, ALERTS, FREEZE_ID, FROZEN_PROXY_URL,
                        LIVE_PROXY_URL, NGINX, PARTS, REPO, ROW_KEYS, RULES_PART, RUN_ID, SLUG, SYSLOG, SYSLOG_AFTER_T, SYSLOG_IN_SPAN, T, LabRig, expected_copy, instant, seconds)

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
    assert rig.env["DEFENDER_CREDENTIAL_PROXY_URL"] == FROZEN_PROXY_URL != LIVE_PROXY_URL
    assert j.first("start_proxy") < j.first("run")
    assert rig.index.read_text().startswith(older), "an existing row was rewritten"
    first, row = rig.rows()
    assert set(row) == ROW_KEYS and isinstance(row["reason"], str)
    assert (row["slug"], row["run_id"], row["binding"], row["verdict"], row["knowledge"]) == (
        SLUG, RUN_ID, rig.binding(), "valid", "abc1234")
    assert instant(row["verified_at"]) > instant("2026-11-08T12:00:00Z")
    assert [json.loads(x) for x in rig.index_at_teardown.splitlines()] == [first, row]
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

    parts, as_of, mutations = rig.ops.stubs
    assert instant(as_of) == instant(T) and mutations == case["overlay"]["mutations"]
    assert not [m for m in rig.cluster.mutations if m["kind"] == "reindex"]


def test_a_variant_without_an_overlay_loads_the_stubs_with_no_mutations(tmp_path):
    """A3/O3: control for the test above; stubs are pinned at T either way."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    rig.launch()

    _parts, as_of, mutations = rig.ops.stubs
    assert instant(as_of) == instant(T) and not mutations


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
    assert rig.ops.marker["dirty"] is False and rig.ops.marker["freeze"] == FREEZE_ID


def test_the_launch_pins_the_clock_restarts_the_node_and_checks_the_copy_in_order(tmp_path):
    """D15/O6: the node restarts after the overlays with the offset T - now (taken just before),
    health is awaited, counts are read after that, and only then does the agent run."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("drift")
    rig.launch()
    j = rig.journal

    expected_offset = (instant(T) - rig.ops.offset_reading).total_seconds()
    assert abs(seconds(rig.ops.offset) - expected_offset) <= 5, rig.ops.offset
    last_overlay = max(i for i, m in enumerate(j) if m[0] == "es" and m[1][1] in ("/_reindex",)
                       or m[0] == "es" and m[1][1].endswith("/_delete_by_query"))
    health = rig.es_at(lambda m, p: p == "/_cluster/health")
    counts = rig.es_at(lambda m, p: p.endswith("/_count") or p.startswith("/_cat/indices"))
    assert last_overlay < j.first("restart_node") < health[-1] < max(counts) < j.first("run")
    assert j.first("load_stubs") < j.first("run")


# -- credentials (A9) ------------------------------------------------------------------------------


def test_the_read_only_user_gets_the_current_password_and_the_node_cert_is_mounted_before_the_proxy(tmp_path):
    """A9: each launch reads the password as it is then, creates the user with it and mounts the live
    node certificate, both before the frozen proxy starts; neither is written into a freeze part."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    parts_before = {p.name: p.read_bytes() for p in (rig.parts / FREEZE_ID).iterdir()}
    rig.launch()
    first_end = len(rig.journal)
    rig.ops.password = "pw-rotated"
    rig.launch()
    slices = [rig.journal.ops()[:first_end], rig.journal.ops()[first_end:]]

    assert [pw for pw, _ in rig.ops.users] == ["pw-0", "pw-rotated"], rig.ops.users
    assert all(up is False for _, up in rig.ops.users) and rig.ops.cert_mounts == [False, False]
    for ops in slices:
        assert ops.index("create_readonly_user") < ops.index("start_proxy"), ops
        assert ops.index("mount_node_cert") < ops.index("start_proxy"), ops
        assert ops.index("mount_node_cert") < ops.index("restart_node"), ops
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
    assert rig.ops.marker is None or rig.ops.marker["dirty"] is True

    rig.launch()

    assert rig.cluster.restores == 2 and rig.cluster.state() == expected_copy("drift")
    assert [r["verdict"] for r in rig.rows()] == ["valid"]


def test_a_copy_with_no_marker_is_restored_whole_over_whatever_it_holds(tmp_path):
    """A4: an unknown copy state (no marker) is never trusted: stray and altered documents in an
    open index are gone after the launch."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    rig.cluster.put(AUTH, "auth-99", {"@timestamp": "2026-10-20T05:00:00Z", "message": "stray"})
    rig.cluster.put(AUTH, "auth-05", {"@timestamp": "2026-10-20T04:50:00Z", "message": "altered"})
    rig.cluster.put(NGINX, "nginx-99", {"@timestamp": "2026-10-20T05:00:00Z", "message": "stray"})
    rig.launch()

    assert rig.cluster.state() == expected_copy("none")
    assert [r["verdict"] for r in rig.rows()] == ["valid"]


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
        pytest.param({}, "write_marker", None, id="marker"),
        pytest.param({}, "load_stubs", None, id="stubs"),
        pytest.param({}, "restart_node", None, id="node-restart"),
        pytest.param({}, "start_proxy", None, id="proxy"),
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
    """A2/O6: not stale: the failing step was reached, nothing runs, no row, the copy is torn down,
    the lock is free and no clean marker is left."""
    rig = LabRig(tmp_path, **rig_kw)
    rig.write_expected_case("drift")
    rig.ops.fail_at = ops_fail
    _fails_to_launch(rig, f"{ops_fail} failed" if ops_fail else f"{reached} failed")

    assert (ops_fail in rig.journal.ops()) if ops_fail else rig.es_at(lambda m, p: reached in p)
    assert "run" not in rig.journal.ops() and rig.rows() == []
    assert "teardown" in rig.journal.ops() and "frozen-engine" not in rig.store.records
    if not ops_fail or ops_fail == "write_marker":     # a copy that was made stays clean when only a service failed
        assert rig.ops.marker is None or rig.ops.marker["dirty"] is True


def test_a_cluster_that_never_turns_green_is_a_launch_failure_with_no_row(tmp_path):
    """O6: "wait for primaries active" gives up after polling health: no run, no row, torn down, lock free."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    rig.cluster.health_status = "red"
    _fails_to_launch(rig)

    assert len(rig.es_at(lambda m, p: p == "/_cluster/health")) >= 1, "health was never polled"
    assert "run" not in rig.journal.ops() and rig.rows() == [] and "frozen-engine" not in rig.store.records
    assert "teardown" in rig.journal.ops()


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
    assert not rig.cluster.requests and rig.ops.stubs is None and rig.ops.marker is None
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
    assert not rig.cluster.requests and rig.ops.stubs is None
    assert rig.rows() == [] and "frozen-engine" not in rig.store.records


def test_a_fixture_without_a_case_file_is_not_a_case(tmp_path):
    """A2/O11: legacy fixtures (alert.json and ground truth only) are refused, not launched."""
    rig = LabRig(tmp_path)
    rig.launch_module
    with pytest.raises(Exception) as caught:
        rig.launch()

    assert not isinstance(caught.value, (AttributeError, TypeError, NameError))
    assert not rig.cluster.requests and rig.rows() == []


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
    assert "teardown" in rig.journal.ops() and "frozen-engine" not in rig.store.records


def test_an_interrupt_during_the_run_tears_down_and_frees_the_engine_without_a_row(tmp_path):
    """O9: Ctrl-C while the agent runs: teardown, lock released, no row."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")

    def interrupt():
        raise KeyboardInterrupt

    rig.run_hook = interrupt
    with pytest.raises(KeyboardInterrupt):
        rig.launch()

    assert "teardown" in rig.journal.ops() and "frozen-engine" not in rig.store.records and rig.rows() == []


def test_teardown_stops_the_services_but_keeps_the_elasticsearch_data(tmp_path):
    """A1: after the run the copy is still there, for the next run or the label; the proxy is down."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("drop")
    rig.launch()

    assert rig.cluster.state() == rig.cluster_at_teardown == expected_copy("drop")
    assert rig.ops.proxy_up is False and rig.journal.last("teardown") > rig.journal.last("run")


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
    assert not rig.cluster.requests and rig.rows() == []
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
    rig = LabRig(tmp_path)
    rig.write_expected_case("none", confirmed=False)
    rig.store.records["frozen-engine"] = "tok-1"

    rig.launch(reference=True, lock_token="tok-1")

    assert rig.store.records["frozen-engine"] == "tok-1" and rig.lock_in_run
    assert "lock.create" not in rig.journal.ops()
