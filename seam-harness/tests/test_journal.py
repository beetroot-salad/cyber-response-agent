from __future__ import annotations

import json

import pytest

from seam_harness.journal import JournalError, RunJournal


def test_journal_refuses_record_overwrite_and_verifies_chain(tmp_path) -> None:
    journal = RunJournal.create(tmp_path, "test")
    record = journal.write_record("stage", "item", {"answer": 1})
    assert record.is_file()
    assert journal.verify() == []

    with pytest.raises(JournalError, match="Refusing to overwrite"):
        journal.write_record("stage", "item", {"answer": 2})


def test_journal_detects_tampering(tmp_path) -> None:
    journal = RunJournal.create(tmp_path, "test")
    record = journal.write_record("stage", "item", {"answer": 1})
    record.write_text(json.dumps({"answer": 2}), encoding="utf-8")
    assert "record hash mismatch" in " ".join(journal.verify())
