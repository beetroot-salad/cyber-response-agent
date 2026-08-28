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

import pytest

from defender._run_paths import contained_payload, resolve_run_bundle
from defender.learning.lead_repository import load_queries, stage_tables

LEAD = "l-001"
SECRET = "STOLEN-FROM-OUTSIDE-THE-RUN"


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


def test_ticket_read_capture_payload_passes_the_gate(tmp_path: Path) -> None:
    """The judge's ticket-read capture is the second by-ref family the gate admits.

    Asserted on the gate DIRECTLY, not through ``load_queries``: the judge's capture rows carry
    no ``lead_id`` (closed_ticket_tool writes seq/system/verb/params/payload_path/exit_code/
    error_class), and ``load_queries`` drops a lead-less row before the gate is consulted — so
    no ticket-read payload reaches ``raw_ref`` today. Driving this family through
    ``load_queries`` would need a forged ``lead_id`` and would certify a row shape production
    never writes."""
    run = tmp_path / "runs" / "case-1"
    (run / "ticket_reads").mkdir(parents=True)
    (run / "ticket_reads" / "3.json").write_text("{}", encoding="utf-8")
    assert contained_payload(run, "ticket_reads/3.json") == run / "ticket_reads" / "3.json"


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
    """Containment is the whole question the read gate asks, and an in-run link answers it.

    It does not survive STAGING — that boundary refuses every link (below) — so this is what
    the gate concedes on the source tree, not a payload the learning copy will still hold."""
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


def test_a_seq_is_ascii_digits_only(tmp_path: Path) -> None:
    """Both seqs are `f"{int}"`, so the shape is ASCII. A str pattern's `\\d` also matches every
    Unicode decimal, which would admit names no writer produces and contradict the ASCII-only
    lead-id alphabet in the same pattern."""
    run = tmp_path / "runs" / "case-1"
    assert contained_payload(run, f"gather_raw/{LEAD}/٣.json") is None
    assert contained_payload(run, "ticket_reads/١.json") is None


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


# Staging — the copy, not the read.
#
# The read gate above judges a path the moment a consumer follows it. Staging runs EARLIER and
# judges nothing: it copies the tables into learning state, and `copy2`/`copytree` handed a link
# write the TARGET's bytes in under an artifact's name. After that copy the planted content is
# an ordinary in-run file and the gate has nothing left to catch. Nothing this system writes is
# ever a link (a boxed run's exit scrub taints a tree holding one), so the boundary bans them.


def _outside_secret(tmp_path: Path) -> Path:
    secret = tmp_path / "outside" / "secret.json"
    secret.parent.mkdir(parents=True, exist_ok=True)
    secret.write_text(SECRET, encoding="utf-8")
    return secret


def _staged_bytes(dst: Path) -> str:
    return "".join(p.read_text(encoding="utf-8", errors="replace")
                   for p in dst.rglob("*") if p.is_file() and not p.is_symlink())


def test_a_symlinked_queries_table_is_not_staged(tmp_path: Path) -> None:
    run = tmp_path / "runs" / "case-1"
    run.mkdir(parents=True)
    (run / "executed_queries.jsonl").symlink_to(_outside_secret(tmp_path))
    dst = tmp_path / "staged"

    refused = stage_tables(run, dst)

    assert SECRET not in _staged_bytes(dst)
    assert not (dst / "executed_queries.jsonl").exists()
    assert refused == [run / "executed_queries.jsonl"], "a refusal the caller can report"


def test_a_symlinked_gather_root_does_not_import_the_target_directory(tmp_path: Path) -> None:
    """`copytree(symlinks=True)` governs what the walk FINDS, never the root it was handed —
    so the flag the read gate leans on says nothing about this case."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "loot.json").write_text(SECRET, encoding="utf-8")
    run = tmp_path / "runs" / "case-1"
    run.mkdir(parents=True)
    (run / "gather_raw").symlink_to(outside, target_is_directory=True)
    dst = tmp_path / "staged"

    refused = stage_tables(run, dst)

    assert SECRET not in _staged_bytes(dst)
    assert not (dst / "gather_raw" / "loot.json").exists()
    assert refused == [run / "gather_raw"]


def test_a_link_inside_the_gather_tree_is_dropped_and_the_rest_still_stages(
    tmp_path: Path,
) -> None:
    """Dropped, not fatal: a dangling link must not cost the run its whole learning pass
    (#705), and every consumer already tolerates a payload that is not there."""
    run = _run_with_query(tmp_path, f"gather_raw/{LEAD}/0.json")
    (run / "gather_raw" / LEAD / "0.json").symlink_to(_outside_secret(tmp_path))
    (run / "gather_raw" / LEAD / "1.json").write_text('{"hit": 1}', encoding="utf-8")
    (run / "gather_raw" / "dangling.json").symlink_to(tmp_path / "never-existed")
    dst = tmp_path / "staged"

    refused = stage_tables(run, dst)

    assert SECRET not in _staged_bytes(dst)
    assert not (dst / "gather_raw" / LEAD / "0.json").exists()
    assert (dst / "gather_raw" / LEAD / "1.json").read_text(encoding="utf-8") == '{"hit": 1}'
    assert (dst / "executed_queries.jsonl").is_file()
    assert set(refused) == {run / "gather_raw" / "dangling.json",
                            run / "gather_raw" / LEAD / "0.json"}


def test_a_symlinked_case_artifact_makes_the_run_unprocessable(tmp_path: Path) -> None:
    """The three artifacts the actor and the judge read AS the case get the opposite posture
    from a payload: substituting one substitutes the case, so persist refuses the run."""
    from defender.learning.core.config import RunUnprocessable
    from defender.learning.core.persist import _copy_shared_inputs

    run = tmp_path / "runs" / "case-1"
    run.mkdir(parents=True)
    (run / "report.md").write_text("---\ndisposition: benign\n---\n", encoding="utf-8")
    (run / "investigation.md").write_text(":L l-001\n", encoding="utf-8")
    (run / "alert.json").symlink_to(_outside_secret(tmp_path))

    with pytest.raises(RunUnprocessable, match="not a regular file"):
        _copy_shared_inputs(run, tmp_path / "learning" / "case-1")


def test_a_source_run_dir_that_is_not_a_string_is_a_missing_bundle(tmp_path: Path) -> None:
    """A queued row is data, not a contract: a non-string here must read as a missing bundle —
    the gate's own posture — rather than raise out of a drain batch mid-flight."""
    runs = tmp_path / "state" / "runs"
    runs.mkdir(parents=True)
    for wrong in (7, None, {"path": "case-1"}, ["case-1"]):
        assert not resolve_run_bundle(runs, wrong).is_dir()
