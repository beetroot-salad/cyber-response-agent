"""Post-flight: agent-state verification, queue rotation, no-commit surfacing."""
from __future__ import annotations

import json
import subprocess

import pytest


def _commit_lesson(tmp_repo, name: str, finding_id: str) -> str:
    a = tmp_repo.author
    body = (
        "---\n"
        f"name: {name}\n"
        "description: a teachable pitfall\n"
        "source_finding_ids:\n"
        f"  - {finding_id}\n"
        "created_at: 2026-05-09T00:00:00+00:00\n"
        "---\n\nbody\n"
    )
    (a.LESSONS_DIR / f"{name}.md").write_text(body)
    tmp_repo.run_git("add", "-A")
    tmp_repo.run_git("commit", "-q", "-m", f"defender: lesson {name}")
    return tmp_repo.run_git("rev-parse", "HEAD").stdout.strip()


def test_committed_finding_consumed_with_commit_sha(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-1", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-1/0", run_id="run-1")

    def fake_invoke(findings, batch_id):
        sha = _commit_lesson(tmp_repo, "lessonA", "run-1/0")
        return {
            "committed": ["run-1/0"],
            "held_forward_bad": [],
            "consumed_skip": [],
            "commit_sha": sha,
        }

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    assert a.run_batch() == 0
    assert a.PENDING_FILE.read_text().strip() == ""
    consumed = [
        json.loads(line)
        for line in a.CONSUMED_FILE.read_text().splitlines() if line.strip()
    ]
    assert len(consumed) == 1
    assert consumed[0]["consumed_category"] == "consumed_committed"
    assert consumed[0]["consumed_commit"] == tmp_repo.run_git("rev-parse", "HEAD").stdout.strip()


def test_held_forward_bad_stays_in_queue(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-2", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-2/0", run_id="run-2")

    def fake_invoke(findings, batch_id):
        # No commit because every candidate was forward-BAD.
        return {
            "committed": [],
            "held_forward_bad": [{"finding_id": "run-2/0", "reason": "regresses-elsewhere"}],
            "consumed_skip": [],
            "commit_sha": None,
        }

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    assert a.run_batch() == 0
    pending = [
        json.loads(line)
        for line in a.PENDING_FILE.read_text().splitlines() if line.strip()
    ]
    assert [p["finding_id"] for p in pending] == ["run-2/0"]
    assert "forward_bad" in pending[0]["held_reason"]
    # held_report.log records the no-commit forward-BAD batch.
    assert a.HELD_REPORT.is_file()
    assert "run-2/0" in a.HELD_REPORT.read_text()


def test_consumed_skip_rotates_out(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-3", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-3/0", run_id="run-3")

    def fake_invoke(findings, batch_id):
        return {
            "committed": [],
            "held_forward_bad": [],
            "consumed_skip": [{"finding_id": "run-3/0", "reason": "already covered"}],
            "commit_sha": None,
        }

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    assert a.run_batch() == 0
    assert a.PENDING_FILE.read_text().strip() == "", "skipped findings must rotate out — never re-trigger"
    consumed = [
        json.loads(line)
        for line in a.CONSUMED_FILE.read_text().splitlines() if line.strip()
    ]
    assert consumed[0]["consumed_category"] == "consumed_skip"
    assert "skip_reason" in consumed[0]


def test_agent_claims_commit_but_head_unchanged_aborts(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-4", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-4/0", run_id="run-4")
    pre_pending = a.PENDING_FILE.read_text()

    def fake_invoke(findings, batch_id):
        # Lie: claim commit_sha that doesn't match HEAD.
        return {
            "committed": ["run-4/0"],
            "held_forward_bad": [],
            "consumed_skip": [],
            "commit_sha": "deadbeef" * 5,
        }

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    rc = a.run_batch()
    assert rc == 2
    # Queue must be untouched.
    assert a.PENDING_FILE.read_text() == pre_pending


def test_agent_skipped_commit_but_left_dirty_aborts(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-5", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-5/0", run_id="run-5")
    pre_pending = a.PENDING_FILE.read_text()

    def fake_invoke(findings, batch_id):
        # Write a lesson but don't commit.
        (a.LESSONS_DIR / "orphan.md").write_text("uncommitted\n")
        return {
            "committed": [],
            "held_forward_bad": [],
            "consumed_skip": [{"finding_id": "run-5/0", "reason": "x"}],
            "commit_sha": None,
        }

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    rc = a.run_batch()
    assert rc == 2
    assert a.PENDING_FILE.read_text() == pre_pending


def test_agent_result_missing_finding_aborts(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-6", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-6/0", run_id="run-6")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-6/1", run_id="run-6")
    pre_pending = a.PENDING_FILE.read_text()

    def fake_invoke(findings, batch_id):
        # Only reports one of two findings.
        return {
            "committed": [],
            "held_forward_bad": [],
            "consumed_skip": [{"finding_id": "run-6/0", "reason": "x"}],
            "commit_sha": None,
        }

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    with pytest.raises(a.AuthorError, match="missing findings"):
        a.run_batch()
    assert a.PENDING_FILE.read_text() == pre_pending


def test_head_touches_non_lessons_aborts(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-7", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-7/0", run_id="run-7")
    pre_pending = a.PENDING_FILE.read_text()

    def fake_invoke(findings, batch_id):
        # Commit something outside lessons/ — should be rejected.
        (tmp_repo.root / "scratch.txt").write_text("oops")
        (a.LESSONS_DIR / "in-scope.md").write_text("---\nname: x\ndescription: y\nsource_finding_ids:\n  - run-7/0\ncreated_at: 2026-05-09T00:00:00+00:00\n---\n\nb\n")
        tmp_repo.run_git("add", "-A")
        tmp_repo.run_git("commit", "-q", "-m", "mixed")
        sha = tmp_repo.run_git("rev-parse", "HEAD").stdout.strip()
        return {
            "committed": ["run-7/0"],
            "held_forward_bad": [],
            "consumed_skip": [],
            "commit_sha": sha,
        }

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    rc = a.run_batch()
    assert rc == 2
    assert a.PENDING_FILE.read_text() == pre_pending
