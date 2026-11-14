"""#1470 O12: the upgrade notes in `defender/CLAUDE.md`, restated for #1345 and #1366. Only the facts a test can read:
which steps and commands the notes no longer name, what the proxy's grant reads, what the drop's upgrade stops."""
from __future__ import annotations

import re
from pathlib import Path

NOTES = Path(__file__).resolve().parents[3] / "CLAUDE.md"
REMOVED = ("set-alert-mapping", "set-system", "delete-system", "set-case", "delete-case", "set-credentials")


def _section(issue: str) -> str:
    text = NOTES.read_text("utf-8")
    found = re.search(rf"^## Upgrade from before #{issue}\b.*?(?=^## |\Z)", text, re.S | re.M)
    assert found, f"premise: the notes have an upgrade section for #{issue}"
    return found.group(0)


def test_1470_o12_the_1366_note_runs_no_import_and_copies_no_credentials_and_sends_the_admin_to_the_api():
    """The #1366 note no longer has the import or the credential-copy steps, names no removed operator command, and says
    the tenant admin changes systems through the API from then on. (O12)"""
    note = _section("1366")
    assert not re.search(r"tenant\.py\s+import|--dry-run", note), "the import step is gone"
    assert [c for c in REMOVED if c in note] == [], "no removed command is named"
    assert not re.search(r"tenant\.py\s+(systems|catalog)\b", note)
    assert re.search(r"PUT\s+\S*/systems/", note), note
    assert re.search(r"tenant admin", note, re.I), note


def test_1470_o12_the_1366_notes_proxy_grant_reads_the_system_versions_and_the_tenant_rows_id_and_state():
    """Step 1's grant for `defender_proxy_reader`: `system_versions` and the `id` and `state` of the tenant row; the
    mark table is not named as read. (O12, O8)"""
    note = _section("1366")
    grant = re.search(r"defender_proxy_reader.{0,300}", note, re.S)
    assert grant, "premise: the note states the role's grant"
    text = grant.group(0)
    assert "system_versions" in text, text
    assert "state" in text, text
    assert re.search(r"\bid\b", text), text
    assert "records_mark" not in text, text


def test_1470_o12_the_1345_note_sets_the_mapping_through_the_api_not_the_operator_command():
    """The #1345 note's step 2 is the `PUT` of the alert mapping; `set-alert-mapping` is not named. (O12, O1)"""
    note = _section("1345")
    assert "set-alert-mapping" not in note
    assert re.search(r"PUT\s+\S*alert-mapping", note), note


def test_1470_o12_the_drop_upgrade_says_to_stop_the_processes_that_read_the_mark_and_to_rebuild_the_job_image():
    """The note for the upgrade that drops the mark tells the operator to stop the API, the credential proxy and the
    workers before migrating and to rebuild the job image (an old image refuses the new records wire). (O12, D-F)"""
    note = _section("1366")
    for word in ("stop", "API", "credential proxy", "worker", "job image"):
        assert re.search(re.escape(word), note, re.I if word == "stop" else 0), f"the note never says {word!r}"
