"""O1/O2: every host record I/O occurrence is migrated or named counted residue."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests import _1165_census as C


@pytest.mark.parametrize("body", [
    "from defender._io import write_guarded as save\ndef f(run_dir):\n save(run_dir / 'x', 'y')",
    "from defender import _io as io\ndef f(run_dir):\n io.rooted_write(run_dir, 'x', 'y', mode='replace')",
    "from defender._io import read_jsonl_rows as rows\ndef f(run_dir):\n return rows(run_dir / 'x')",
    "import os as syscalls\ndef f(run_dir):\n return syscalls.open(run_dir / 'x', 1)",
    "import shutil as copy\ndef f(run_dir):\n copy.copyfile(run_dir / 'x', run_dir / 'y')",
    "from pathlib import Path\ndef f(run_dir):\n return (run_dir / 'x').read_text()",
    "from defender._io import write_guarded\nSAVE = write_guarded\ndef f(run_dir):\n SAVE(run_dir / 'x', 'y')",
    "from defender._io import write_guarded\ndef f(run_dir):\n return write_guarded",
])
def test_every_swept_io_shape_is_rejected_without_residue(body):
    hits = C.census_source("runtime/planted.py", body)
    assert hits, "the architectural check must observe the planted bypass"
    assert C.deviations(hits, {})


def test_handled_record_operations_are_not_path_io():
    body = """
def f(run):
    run.tables.queries.seed([{'lead_id': 'l-001'}])
    run.tables.queries.append([{'lead_id': 'l-001'}])
    run.tables.payloads('l-001', 0).write(b'opaque')
    run.documents.report.write('report')
    run.observability.wire_log.append_text('line\\n')
"""
    assert C.census_source("runtime/planted.py", body) == []


def test_resolved_record_byte_reads_are_allowed_but_path_and_unknown_receivers_are_not():
    source = """
from defender.run_repository import Run as Investigation, RecordHandle as Record
def f(run: Investigation, record: Record, mystery):
    alias = record
    alias.read_bytes()
    alias.replace("record")
    run.facts.alert_record.replace("record")
    run.facts.alert.read_bytes()
    run.tables.payloads('l-001', 0).read_bytes()
    record.path.read_bytes()
    mystery.read_bytes()
    record.path.replace("outside")
    mystery.replace("outside")
"""
    hits = C.census_source("runtime/planted.py", source)
    assert len(hits) == 4
    assert {hit.expression for hit in hits} == {"record.path", "mystery"}
    assert C.deviations(hits, {})


def test_duplicate_bypass_in_an_allowed_scope_is_not_collapsed():
    body = "from defender._io import read_text_utf8\ndef f(path):\n return read_text_utf8(path)\n"
    hits = C.census_source("runtime/planted.py", body)
    assert len(hits) == 1
    allowed = {hits[0].key: (1, "nonrecord", ("path",))}
    assert C.deviations(hits, allowed) == []
    doubled = body.replace(" return read_text_utf8(path)",
                           " read_text_utf8(path)\n return read_text_utf8(path)")
    violations = C.deviations(C.census_source("runtime/planted.py", doubled), allowed)
    assert any("duplicate" in violation for violation in violations)
    assert any("stale" in violation for violation in C.deviations([], allowed))


def test_nonrecord_residue_cannot_be_reused_for_a_run_record():
    plain = "from defender._io import read_text_utf8\ndef f(path):\n return read_text_utf8(path)\n"
    hits = C.census_source("runtime/planted.py", plain)
    residue = {hits[0].key: (1, "nonrecord", ("path",))}
    changed = plain.replace("read_text_utf8(path)", "read_text_utf8(run_dir / 'x')")
    assert C.deviations(C.census_source("runtime/planted.py", changed), residue)


def test_unknown_target_inside_an_existing_nonrecord_scope_is_not_exempt():
    residue = {("runtime.bash_policy", "_load_policy", "read_text_utf8"):
               (1, "nonrecord", ("path",))}
    source = "from defender._io import read_text_utf8\ndef _load_policy(path):\n return read_text_utf8(path)"
    assert C.deviations(C.census_source("runtime/bash_policy.py", source), residue) == []
    unknown = source.replace("read_text_utf8(path)", "read_text_utf8(mystery)")
    assert any("unclassified" in finding for finding in C.deviations(
        C.census_source("runtime/bash_policy.py", unknown), residue))


def test_owner_alias_target_is_classified_as_record():
    source = """
from defender.run_repository import RunPaths
from defender._io import write_guarded
def f(run_dir):
    owner = RunPaths(run_dir)
    target = owner.report
    alias = target
    write_guarded(alias, 'report')
"""
    hits = C.census_source("runtime/planted.py", source)
    assert len(hits) == 1
    assert hits[0].target == "record"


def test_unclassified_target_is_still_reported():
    hits = C.census_source("runtime/planted.py",
                           "from defender._io import write_guarded\ndef f(mystery):\n write_guarded(mystery, 'x')")
    assert len(hits) == 1
    assert hits[0].target == "unresolved"
    assert C.deviations(hits, {})


def test_pure_json_parsing_is_not_io():
    assert C.census_source("runtime/planted.py",
                           "from defender._io import load_json_artifact\ndef f(text):\n return load_json_artifact(text)") == []


def test_missing_sweep_directory_and_unparseable_modules_fail(tmp_path):
    with pytest.raises(ValueError, match="missing swept directory"):
        C.collect(tmp_path)
    with pytest.raises(SyntaxError):
        C.census_source("runtime/broken.py", "def !")


# Exact residual occurrences are intentionally small, categorized, and not regenerated from
# implementation. The live-state files and durable record writers are not exemptions.
RESIDUE = {
    ("runtime.driver._build", "_fold_decision", "read_text_utf8"): (1, "m_read"),
    ("hooks.inject_system_skill_description", "read_description", "read_text_soft"): (1, "nonrecord", ('skill_path',)),
    ("runtime.bash_policy", "_load_policy", "read_text_utf8"): (1, "nonrecord", ('path',)),
    ("runtime.box._docker", "_own_container_ids", "read_text_soft"): (2, "nonrecord", ('hostname_path', 'mountinfo_path')),
    ("runtime.box._clock", "write_clock", "write_guarded"): (1, "job_state", ('clock_file',)),
    ("runtime.box._clock", "prepare_clock", "guarded_mkdir"): (1, "job_state", ('where',)),
    ("runtime.box._clock", "prepare_clock", "write_guarded"): (1, "job_state", ('clock_file',)),
    ("runtime.box._clock", "remove_clock", "shutil.rmtree"): (1, "job_state", ('clock_file.parent',)),
    ("runtime.box._stage", "_remove", "shutil.rmtree"): (1, "model_view", ('entry',)),
    ("runtime.box._stage", "_remove", ".unlink"): (1, "model_view", ('entry',)),
    ("runtime.box._stage", "_same_bytes", "builtins.open"): (2, "model_view", ('a', 'b')),
    ("runtime.box._stage", "_carry_file", "shutil.copy2"): (1, "model_view", ('entry.path',)),
    ("runtime.box._stage", "_mirror_tree", "guarded_mkdir"): (1, "model_view", ('target',)),
    ("runtime.box._stage", "make_staging_tree", "guarded_mkdir"): (1, "model_view", ('tree.run_view',)),
    ("runtime.box._stage", "make_staging_tree", ".symlink_to"): (
        2, "model_view", ("root / MODEL_DEFENDER.relative_to('/')", "root / MODEL_AGENT.relative_to('/')")),
    # The finalizer holds this cleanup callable; the census records that reference.
    ("runtime.box._stage", "staged_executor", "shutil.rmtree"): (1, "model_view", ('<reference>',)),
    ("runtime.box._image", "_read", ".read_bytes"): (1, "nonrecord", ('tree / name',)),
    # #1108 P3 (D7): a read-only mount is verified by reading an existing host file back
    # (a code mount's `MOUNT_CHECK` or a data mount's first regular file) — never a run record.
    ("runtime.box._lifecycle", "_check_mount_sentinel", "read_text_utf8"): (1, "probe", ('source / relative',)),
    ("runtime.box._lifecycle", "_plant", "write_guarded"): (1, "probe", ('sentinel',)),
    ("runtime.box._lifecycle", "_probe_sentinel", ".unlink"): (2, "probe", ('sentinel',)),
    ("runtime.box._lifecycle", "stop_and_scrub", "sweep_staged"): (1, "cleanup", ('tree',)),
    ("runtime.box._oracle", "_make_runner", "guarded_mkdir"): (1, "nonrecord", ('dest.parent',)),
    ("runtime.box._oracle", "_make_runner", "read_bytes_capped"): (1, "nonrecord", ('CHECKOUT / rel',)),
    ("runtime.box._oracle", "_make_runner", "shutil.rmtree"): (1, "nonrecord", ('runner',)),
    ("runtime.box._oracle", "_make_runner", "write_guarded"): (1, "nonrecord", ('dest',)),
    ("runtime.box._oracle", "start_oracle_box", "shutil.rmtree"): (1, "nonrecord", ('runner',)),
    ("runtime.box._oracle", "start_oracle_box.discard", "shutil.rmtree"): (2, "nonrecord", ('runner', 'scratch')),
    ("runtime.box._oracle", "stop_oracle_box", "shutil.rmtree"): (1, "nonrecord", ('folder',)),
    ("runtime.driver", "_stop_before_main", "write_guarded"): (1, "retiring"),
    # #1255 extracted the existing empty tool-trace fallback; #1165 N-c still
    # retires this projection separately. Its record target and count are unchanged.
    ("runtime.driver", "_write_trace_or_empty", "write_guarded"): (
        1, "retiring", ('RunPaths(run_dir).tool_trace',)),
    ("runtime.driver._build", "_gather_instructions", "read_text_utf8"): (1, "nonrecord", ("defender_dir / 'skills' / 'gather' / 'SKILL.md'",)),
    ("runtime.driver._prompts", "_main_instructions", "read_text_utf8"): (1, "nonrecord", ("defender_dir / 'SKILL.md'",)),
    ("runtime.lead_zero", "run_correlation", "read_text_utf8"): (1, "m_read"),
    ("runtime.lessons_engine.lessons_fm", "cmd_show", "read_text_utf8"): (1, "nonrecord", ('lesson',)),
    ("runtime.lessons_engine.lessons_frontier", "main", "read_text_soft"): (1, "nonrecord", ('Path(ns.investigation)',)),
    # Explicit non-run backend paths: learning loggers and worktree scrubs share these
    # utilities. Run integrations are separately driven with the handed record handles.
    ("runtime.observe", "RequestLogger.__init__", "open_guarded"): (1, "non_run", ('path',)),
    ("runtime.observe", "stage_trace_path", "guarded_mkdir"): (1, "non_run"),
    ("runtime.observe", "write_trace", "write_guarded"): (1, "retiring"),
    ("runtime.orient", "_invlang_grammar", "read_text_soft"): (1, "nonrecord", ("defender_dir / 'skills' / 'invlang' / 'SKILL.md'",)),
    ("runtime.review", "role_prompt", "read_text_utf8"): (1, "nonrecord", ('path',)),
    ("runtime.scrub", "_write_verdict", "write_guarded"): (1, "non_run", ('verdict_path(tree)',)),
    ("runtime.scrub", "mark_unsandboxed", "read_text_utf8"): (1, "non_run", ('p',)),
    ("runtime.scrub", "tree_unsandboxed", "read_text_utf8"): (1, "non_run", ('verdict_path(tree)',)),
    ("runtime.scrub", "tree_verified", "read_text_utf8"): (1, "non_run", ('p',)),
    ("runtime.session_store", "open_store", "guarded_mkdir"): (1, "session_store", ('path.parent',)),
    # The SQL shim reads the model's file operands and operates only inside the box.
    ("runtime.sql_engine.sql", "_inferred_load", "builtins.open"): (1, "model_tools"),
    ("runtime.sql_engine.sql", "_load_rows", "builtins.open"): (1, "model_tools"),
    ("runtime.sql_engine.sql", "_run", "shutil.rmtree"): (1, "nonrecord", ('scratch',)),
    ("runtime.tenant_settings", "read_regular_bytes", "getattr(os)"): (1, "nonrecord", ('os',)),
    ("runtime.tenant_settings", "read_regular_bytes", "os.open"): (1, "nonrecord", ('path',)),
    ("runtime.tools._files", "_write_operand", "hold"): (1, "model_tools", ('root',)),
    ("runtime.verb_roster", "audit_read_surfaces", "read_text_utf8"): (1, "nonrecord", ('path',)),
    ("runtime.verbs", "read_roster", "read_bytes_capped"): (1, "nonrecord", ('path',)),
}


@pytest.mark.gate
def test_running_investigation_io_equals_declared_counted_residue():
    package = Path(__file__).resolve().parents[1]
    assert C.deviations(C.collect(package), RESIDUE) == []


def test_working_file_alias_keeps_member_classification_without_exempting_fact_reads():
    body = """
from defender.run_repository import RunPaths
from defender._io import read_text_utf8
def f(run_dir):
    inv = RunPaths(run_dir).investigation
    alias = inv
    read_text_utf8(alias)
"""
    hits = C.census_source("runtime/planted.py", body)
    key = ("runtime.planted", "f", "read_text_utf8")
    assert C.deviations(hits, {key: (1, "m_read")}) == []
    fact = C.census_source("runtime/planted.py", body.replace(".investigation", ".alert_record"))
    assert C.deviations(fact, {key: (1, "m_read")})
