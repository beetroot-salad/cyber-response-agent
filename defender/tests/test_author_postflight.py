"""Post-flight: agent-state verification, queue rotation, no-commit surfacing.

The agent runs **no git**: each fake ``invoke_agent`` leaves ``defender/lessons/`` in
its final state (writes files, never commits) and returns the commit message as data.
The loop (``commit_lessons``) is the sole committer.
"""
from __future__ import annotations

import json

import pytest


def _write_lesson(tmp_repo, name: str, finding_id: str) -> None:
    """Write a lesson into the working tree — no git (the loop commits)."""
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


def test_committed_finding_consumed(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-1", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-1/0", run_id="run-1")

    def fake_invoke(findings, batch_id):
        _write_lesson(tmp_repo, "lessonA", "run-1/0")  # no git
        return {
            "committed": ["run-1/0"],
            "held_forward_bad": [],
            "consumed_skip": [],
            "commit_message": "defender: lesson lessonA",
        }

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    assert a.run_batch() == 0
    # The loop committed the lesson the agent left in the working tree.
    head_files = tmp_repo.run_git(
        "show", "--name-only", "--pretty=format:", "HEAD"
    ).stdout.split()
    assert head_files == ["defender/lessons/lessonA.md"]
    assert a.PENDING_FILE.read_text().strip() == ""
    consumed = [
        json.loads(line)
        for line in a.CONSUMED_FILE.read_text().splitlines() if line.strip()
    ]
    assert len(consumed) == 1
    assert consumed[0]["consumed_category"] == "consumed_committed"
    assert consumed[0]["consumed_commit"] == tmp_repo.run_git("rev-parse", "HEAD").stdout.strip()


def test_committed_finding_without_commit_message_aborts(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-1b", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-1b/0", run_id="run-1b")
    pre_pending = a.PENDING_FILE.read_text()

    def fake_invoke(findings, batch_id):
        _write_lesson(tmp_repo, "lessonB", "run-1b/0")  # corpus dirty, but no message
        return {
            "committed": ["run-1b/0"],
            "held_forward_bad": [],
            "consumed_skip": [],
        }

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    assert a.run_batch() == 2
    assert a.PENDING_FILE.read_text() == pre_pending
    assert not a.CONSUMED_FILE.exists()


def test_held_forward_bad_stays_in_queue(tmp_repo, helpers, monkeypatch):
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-2", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-2/0", run_id="run-2")

    def fake_invoke(findings, batch_id):
        # No commit because every candidate was forward-BAD (reverted → corpus clean).
        return {
            "committed": [],
            "held_forward_bad": [{"finding_id": "run-2/0", "reason": "regresses-elsewhere"}],
            "consumed_skip": [],
            "commit_message": None,
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
            "commit_message": None,
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


def test_committed_but_corpus_clean_aborts(tmp_repo, helpers, monkeypatch):
    """``committed`` non-empty but the corpus is clean (agent claimed a commit but left
    no edits) ⇒ inconsistent; refuse to rotate."""
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-4", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-4/0", run_id="run-4")
    pre_pending = a.PENDING_FILE.read_text()

    def fake_invoke(findings, batch_id):
        # Reports a commit but wrote nothing — corpus stays clean.
        return {
            "committed": ["run-4/0"],
            "held_forward_bad": [],
            "consumed_skip": [],
            "commit_message": "defender: lesson batch",
        }

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    assert a.run_batch() == 2
    assert a.PENDING_FILE.read_text() == pre_pending


def test_no_commit_but_left_corpus_edits_aborts(tmp_repo, helpers, monkeypatch):
    """``committed`` empty but the corpus is dirty ⇒ inconsistent; refuse to rotate."""
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-5", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-5/0", run_id="run-5")
    pre_pending = a.PENDING_FILE.read_text()

    def fake_invoke(findings, batch_id):
        # Write a lesson but report no commit.
        (a.LESSONS_DIR / "orphan.md").write_text("uncommitted\n")
        return {
            "committed": [],
            "held_forward_bad": [],
            "consumed_skip": [{"finding_id": "run-5/0", "reason": "x"}],
            "commit_message": None,
        }

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    assert a.run_batch() == 2
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
            "commit_message": None,
        }

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    rc = a.run_batch()
    assert rc == 2
    assert a.PENDING_FILE.read_text() == pre_pending


def test_prestaged_stray_does_not_ride_into_lesson_commit(
    tmp_repo, helpers, monkeypatch
):
    """A file already **staged** outside defender/lessons/ before the batch (a sibling
    author's _draft/ deposit left in the shared index) is in ``baseline_stray``, so the
    scope gate tolerates it — but the pathspec-scoped commit must NOT sweep it into the
    lesson commit. A bare index-global ``git commit`` would; this guards commit_lessons'
    ``-- defender/lessons/`` pathspec."""
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-8", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-8/0", run_id="run-8")
    # Pre-stage a stray OUTSIDE the corpus, present before the agent runs.
    (tmp_repo.root / "sibling_draft.md").write_text("unrelated staged work\n")
    tmp_repo.run_git("add", "sibling_draft.md")

    def fake_invoke(findings, batch_id):
        _write_lesson(tmp_repo, "lessonH", "run-8/0")  # no git
        return {
            "committed": ["run-8/0"],
            "held_forward_bad": [],
            "consumed_skip": [],
            "commit_message": "defender: lesson lessonH",
        }

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    assert a.run_batch() == 0
    head_files = tmp_repo.run_git(
        "show", "--name-only", "--pretty=format:", "HEAD"
    ).stdout.split()
    assert head_files == ["defender/lessons/lessonH.md"]
    assert "sibling_draft.md" not in head_files
    # The stray stays staged-but-uncommitted, untouched by the lesson commit.
    status = tmp_repo.run_git(
        "status", "--porcelain", "--", "sibling_draft.md"
    ).stdout
    assert status.startswith("A  ")
    assert a.PENDING_FILE.read_text().strip() == ""  # finding rotated out


@pytest.mark.parametrize(
    "agent_result",
    [
        {
            "committed": [],
            "held_forward_bad": [{"finding_id": "run-6b/0", "reason": "x"}],
            "consumed_skip": [{"finding_id": "run-6b/0", "reason": "x"}],
            "commit_message": None,
        },
        {
            "committed": [],
            "held_forward_bad": [],
            "consumed_skip": [
                {"finding_id": "run-6b/0", "reason": "x"},
                {"finding_id": "run-6b/0", "reason": "x"},
            ],
            "commit_message": None,
        },
    ],
)
def test_agent_result_duplicate_classification_aborts(
    tmp_repo, helpers, monkeypatch, agent_result
):
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-6b", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-6b/0", run_id="run-6b")
    pre_pending = a.PENDING_FILE.read_text()

    def fake_invoke(findings, batch_id):
        return agent_result

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    rc = a.run_batch()
    assert rc == 2
    assert a.PENDING_FILE.read_text() == pre_pending
    assert not a.CONSUMED_FILE.exists()


def test_agent_writes_outside_lessons_aborts(tmp_repo, helpers, monkeypatch):
    """Scope gate: a working-tree change outside the corpus (the path-scoped commit
    would ignore it) fails verification rather than committing silently."""
    a = tmp_repo.author
    helpers.write_source_refs(a.RUNS_DIR, "run-7", "benign")
    helpers.write_finding(a.PENDING_FILE, finding_id="run-7/0", run_id="run-7")
    pre_pending = a.PENDING_FILE.read_text()

    def fake_invoke(findings, batch_id):
        # Write a file outside lessons/ (+ a valid lesson) — no git.
        (tmp_repo.root / "scratch.txt").write_text("oops")
        _write_lesson(tmp_repo, "in-scope", "run-7/0")
        return {
            "committed": ["run-7/0"],
            "held_forward_bad": [],
            "consumed_skip": [],
            "commit_message": "defender: lesson in-scope",
        }

    monkeypatch.setattr(a, "invoke_agent", fake_invoke)
    rc = a.run_batch()
    assert rc == 2
    assert a.PENDING_FILE.read_text() == pre_pending
