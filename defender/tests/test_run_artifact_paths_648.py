"""#648 — a path recorded in a run artifact is a label, not an address.

The run dir is the box's rw bind, so model-written bash can write the queries table and the
gather tree. Two host-side readers used to turn a recorded string into an `open()` under a
LEXICAL guard: the payload reader rejected paths that were spelled absolute, and the bundle
resolver TRUSTED paths that were spelled absolute. Neither asked where the value lands.

Both gates matter and they answer different questions, so the symlink case is the load-bearing
one here: it is spelled exactly like a real artifact and still escapes, which is precisely what
a shape-only fix passes.
"""
from __future__ import annotations

import json
from pathlib import Path

from defender._run_paths import contained_payload, resolve_run_bundle
from defender.learning.lead_repository import load_queries

LEAD = "l-001"


def _run_with_query(tmp_path: Path, payload_path) -> Path:
    """A run dir whose queries table holds one row pointing at `payload_path`."""
    run = tmp_path / "runs" / "case-1"
    (run / "gather_raw" / LEAD).mkdir(parents=True, exist_ok=True)
    row = {"lead_id": LEAD, "seq": 0, "system": "elastic", "payload_path": payload_path}
    (run / "executed_queries.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    return run


def _raw_ref(tmp_path: Path, payload_path) -> Path | None:
    rows = load_queries(_run_with_query(tmp_path, payload_path))
    assert len(rows) == 1, "the row itself survives; only its by-ref payload is refused"
    return rows[0].raw_ref


def test_gather_payload_resolves_when_it_names_a_real_artifact(tmp_path: Path) -> None:
    run = _run_with_query(tmp_path, f"gather_raw/{LEAD}/0.json")
    (run / "gather_raw" / LEAD / "0.json").write_text('{"hit": 1}', encoding="utf-8")
    ref = load_queries(run)[0].raw_ref
    assert ref is not None
    assert ref.read_text(encoding="utf-8") == '{"hit": 1}'
    assert str(ref.relative_to(run)) == f"gather_raw/{LEAD}/0.json"


def test_ticket_read_capture_payload_resolves(tmp_path: Path) -> None:
    """The judge's ticket-read capture is the second by-ref family and stays readable."""
    run = _run_with_query(tmp_path, "ticket_reads/3.json")
    (run / "ticket_reads").mkdir()
    (run / "ticket_reads" / "3.json").write_text("{}", encoding="utf-8")
    assert load_queries(run)[0].raw_ref is not None


def test_traversal_out_of_the_run_dir_is_refused(tmp_path: Path) -> None:
    (tmp_path / "secret.json").write_text("stolen", encoding="utf-8")
    assert _raw_ref(tmp_path, "gather_raw/../../../secret.json") is None
    assert _raw_ref(tmp_path, "../../secret.json") is None


def test_absolute_payload_path_is_refused(tmp_path: Path) -> None:
    secret = tmp_path / "secret.json"
    secret.write_text("stolen", encoding="utf-8")
    assert _raw_ref(tmp_path, str(secret)) is None


def test_symlink_wearing_the_expected_artifact_name_is_refused(tmp_path: Path) -> None:
    """The shape gate cannot see this one — the name is exactly what the gather lane writes.
    Containment is checked on the RESOLVED target, so the link's destination decides."""
    secret = tmp_path / "secret.json"
    secret.write_text("stolen", encoding="utf-8")
    run = _run_with_query(tmp_path, f"gather_raw/{LEAD}/0.json")
    (run / "gather_raw" / LEAD / "0.json").symlink_to(secret)
    assert load_queries(run)[0].raw_ref is None


def test_symlink_staying_inside_the_run_dir_is_allowed(tmp_path: Path) -> None:
    """Staging copies the gather tree links-and-all, so an in-run link is a normal artifact."""
    run = _run_with_query(tmp_path, f"gather_raw/{LEAD}/0.json")
    (run / "gather_raw" / "real.json").write_text("ok", encoding="utf-8")
    (run / "gather_raw" / LEAD / "0.json").symlink_to(run / "gather_raw" / "real.json")
    ref = load_queries(run)[0].raw_ref
    assert ref is not None
    assert ref.read_text(encoding="utf-8") == "ok"


def test_a_payload_path_that_is_not_a_string_does_not_crash_the_read(tmp_path: Path) -> None:
    assert _raw_ref(tmp_path, 7) is None
    assert _raw_ref(tmp_path, {"path": "x"}) is None
    assert _raw_ref(tmp_path, None) is None


def test_payload_outside_the_two_known_families_is_refused(tmp_path: Path) -> None:
    """A well-formed, contained path is still refused when it is not an artifact a run writes
    — the gate is a whitelist of what the system produces, not a traversal filter."""
    run = _run_with_query(tmp_path, "alert.json")
    (run / "alert.json").write_text("{}", encoding="utf-8")
    assert load_queries(run)[0].raw_ref is None
    assert contained_payload(run, f"gather_raw/{LEAD}/0.txt") is None
    assert contained_payload(run, f"gather_raw/{LEAD}/notaseq.json") is None
    assert contained_payload(run, "gather_raw/not-a-lead-id/0.json") is None


def test_source_run_dir_never_addresses_outside_the_runs_root(tmp_path: Path) -> None:
    """The bundle is always `runs_dir / <run_id>`, so only the last segment is honored —
    the absolute branch that used to be taken verbatim is gone."""
    runs = tmp_path / "state" / "runs"
    assert resolve_run_bundle(runs, "/etc/shadow") == runs / "shadow"
    assert resolve_run_bundle(runs, "../../../etc/") == runs / "etc"
    assert resolve_run_bundle(runs, "defender/learning/runs/case-1/") == runs / "case-1"
    assert resolve_run_bundle(runs, str(tmp_path / "elsewhere" / "case-1")) == runs / "case-1"


def test_degenerate_source_run_dir_is_not_the_runs_root_itself(tmp_path: Path) -> None:
    """`runs_dir` exists, so mapping a nameless input onto it would pass a caller's
    `is_dir()` bundle check and author from a bundle that is not one."""
    runs = tmp_path / "state" / "runs"
    runs.mkdir(parents=True)
    for degenerate in ("/", ".", "..", ""):
        assert resolve_run_bundle(runs, degenerate) != runs
        assert not resolve_run_bundle(runs, degenerate).is_dir()
