"""Tests for the lint_working_io gate: every file I/O occurrence on a run's records is a handled record
operation or a named, counted residue."""
from __future__ import annotations

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_working_io")


@pytest.mark.parametrize("body", [
    "from defender._io import sweep_staged\ndef f(run_dir):\n sweep_staged(run_dir)",
    "from defender._filesystem.write import sweep_staged as sweep\ndef f(run_dir):\n sweep(run_dir)",
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
    hits = _GATE.census_source("runtime/planted.py", body)
    assert hits, "the architectural check must observe the planted bypass"
    assert _GATE.deviations(hits, {})


def test_handled_record_operations_are_not_path_io():
    body = """
def f(run):
    run.tables.queries.seed([{'lead_id': 'l-001'}])
    run.tables.queries.append([{'lead_id': 'l-001'}])
    run.tables.payloads('l-001', 0).write(b'opaque')
    run.documents.report.write('report')
    run.observability.wire_log.append_text('line\\n')
"""
    assert _GATE.census_source("runtime/planted.py", body) == []


def test_resolved_record_byte_reads_are_allowed_but_path_and_unknown_receivers_are_not():
    source = """
from defender.records import Run as Investigation, RecordHandle as Record
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
    hits = _GATE.census_source("runtime/planted.py", source)
    assert len(hits) == 4
    assert {hit.expression for hit in hits} == {"record.path", "mystery"}
    assert _GATE.deviations(hits, {})


def test_duplicate_bypass_in_an_allowed_scope_is_not_collapsed():
    body = "from defender._io import read_text_utf8\ndef f(path):\n return read_text_utf8(path)\n"
    hits = _GATE.census_source("runtime/planted.py", body)
    assert len(hits) == 1
    allowed = {hits[0].key: (1, "nonrecord", ("path",))}
    assert _GATE.deviations(hits, allowed) == []
    doubled = body.replace(" return read_text_utf8(path)",
                           " read_text_utf8(path)\n return read_text_utf8(path)")
    violations = _GATE.deviations(_GATE.census_source("runtime/planted.py", doubled), allowed)
    assert any("duplicate" in violation for violation in violations)
    assert any("stale" in violation for violation in _GATE.deviations([], allowed))


def test_nonrecord_residue_cannot_be_reused_for_a_run_record():
    plain = "from defender._io import read_text_utf8\ndef f(path):\n return read_text_utf8(path)\n"
    hits = _GATE.census_source("runtime/planted.py", plain)
    residue = {hits[0].key: (1, "nonrecord", ("path",))}
    changed = plain.replace("read_text_utf8(path)", "read_text_utf8(run_dir / 'x')")
    assert _GATE.deviations(_GATE.census_source("runtime/planted.py", changed), residue)


def test_unknown_target_inside_an_existing_nonrecord_scope_is_not_exempt():
    residue = {("runtime.bash_policy", "_load_policy", "read_text_utf8"):
               (1, "nonrecord", ("path",))}
    source = "from defender._io import read_text_utf8\ndef _load_policy(path):\n return read_text_utf8(path)"
    assert _GATE.deviations(_GATE.census_source("runtime/bash_policy.py", source), residue) == []
    unknown = source.replace("read_text_utf8(path)", "read_text_utf8(mystery)")
    assert any("unclassified" in finding for finding in _GATE.deviations(
        _GATE.census_source("runtime/bash_policy.py", unknown), residue))


def test_owner_alias_target_is_classified_as_record():
    source = """
from defender.records import RunPaths
from defender._io import write_guarded
def f(run_dir):
    owner = RunPaths(run_dir)
    target = owner.report
    alias = target
    write_guarded(alias, 'report')
"""
    hits = _GATE.census_source("runtime/planted.py", source)
    assert len(hits) == 1
    assert hits[0].target == "record"


def test_unclassified_target_is_still_reported():
    hits = _GATE.census_source("runtime/planted.py",
                           "from defender._io import write_guarded\ndef f(mystery):\n write_guarded(mystery, 'x')")
    assert len(hits) == 1
    assert hits[0].target == "unresolved"
    assert _GATE.deviations(hits, {})


def test_pure_json_parsing_is_not_io():
    assert _GATE.census_source("runtime/planted.py",
                           "from defender._io import load_json_artifact\ndef f(text):\n return load_json_artifact(text)") == []


def test_missing_sweep_directory_and_unparseable_modules_fail(tmp_path):
    with pytest.raises(ValueError, match="missing swept directory"):
        _GATE.collect(tmp_path)
    with pytest.raises(SyntaxError):
        _GATE.census_source("runtime/broken.py", "def !")
    assert _GATE.main(["--root", str(tmp_path)]) == 2


def test_working_file_alias_keeps_member_classification_without_exempting_fact_reads():
    body = """
from defender.records import RunPaths
from defender._io import read_text_utf8
def f(run_dir):
    inv = RunPaths(run_dir).investigation
    alias = inv
    read_text_utf8(alias)
"""
    hits = _GATE.census_source("runtime/planted.py", body)
    key = ("runtime.planted", "f", "read_text_utf8")
    assert _GATE.deviations(hits, {key: (1, "m_read")}) == []
    fact = _GATE.census_source("runtime/planted.py", body.replace(".investigation", ".alert_record"))
    assert _GATE.deviations(fact, {key: (1, "m_read")})


def test_the_shipped_tree_equals_the_declared_residue():
    assert _GATE.scan(_GATE.DEFENDER) == []
