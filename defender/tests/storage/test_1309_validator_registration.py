"""The records write gate gets the invlang validator handed in (#1309 d): it refuses, rather
than passes text unvalidated, until the validator has registered, and the roots that write
investigations register it by loading it."""
from __future__ import annotations

import subprocess
import sys

import pytest

from defender.records import _artifact_schema as schema


@pytest.fixture
def unregistered():
    held = schema._diagnose, schema._warn_diagnostics
    schema._diagnose = schema._warn_diagnostics = None
    try:
        yield
    finally:
        schema._diagnose, schema._warn_diagnostics = held


def test_investigation_write_gate_refuses_until_the_validator_registers(unregistered):
    with pytest.raises(schema.ValidatorNotRegistered):
        schema.validate_investigation("anything", None)


def test_close_gate_does_not_fail_open_without_the_validator(unregistered):
    with pytest.raises(schema.ValidatorNotRegistered):
        schema.committed_investigation_reason("anything")


def test_report_gate_needs_no_validator(unregistered):
    assert schema.validate_report("not frontmatter") is not None


@pytest.mark.parametrize("module", ["defender.run_common", "defender.learning.branch.cli"])
def test_a_writing_root_registers_the_validator_on_import(module):
    probe = (
        f"import {module}\n"
        "from defender.records import _artifact_schema as s\n"
        "raise SystemExit(0 if s._diagnose is not None else 1)\n"
    )
    assert subprocess.run([sys.executable, "-c", probe]).returncode == 0
