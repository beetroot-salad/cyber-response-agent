"""Curator GLM port: kept-envelope survival (rollback, dirty cross-check, scope gate, idempotent redrain, no agent git) and per-spawn trace distinctness."""
from __future__ import annotations

import logging
import os
from dataclasses import replace
from pathlib import Path


from defender.tests._stage_args import as_curator_stage_args  # noqa: E402
from defender._io import read_jsonl_rows
from defender.learning.core.state import FINDINGS


def _rows_without_attempts(text: str) -> list[dict]:
    """The queue's rows with the retirement counter dropped.

    #719: a post-agent abort now BUMPS every row it was authoring (behaviour change 2 of
    four), so "the queue is intact for retry" is no longer a byte comparison — the rows
    themselves must be unchanged, and the count must have moved by exactly one."""
    import json as _json

    return [
        {k: v for k, v in _json.loads(line).items() if k != "attempts"}
        for line in text.splitlines() if line.strip()
    ]


def _attempts(text: str) -> list[int]:
    import json as _json

    return [_json.loads(line).get("attempts") for line in text.splitlines() if line.strip()]


def _write_lesson(tmp_repo, name: str, finding_id: str) -> None:
    """Write a lesson into the working tree — the agent runs NO git (the loop commits)."""
    body = (
        "---\n"
        f"name: {name}\n"
        "description: a teachable pitfall\n"
        "source_finding_ids:\n"
        f"  - {finding_id}\n"
        "created_at: 2026-05-09T00:00:00+00:00\n"
        "---\n\nbody\n"
    )
    (tmp_repo.paths.lessons_dir / f"{name}.md").write_text(body)


def _commit_count(tmp_repo) -> int:
    return int(tmp_repo.run_git("rev-list", "--count", "HEAD").stdout.strip())


def _head_files(tmp_repo) -> list[str]:
    return tmp_repo.run_git(
        "show", "--name-only", "--pretty=format:", "HEAD"
    ).stdout.split()


def test_survival_partial_write_rollback(tmp_repo, helpers):
    """A mid-batch fault (the in-process ``run_stage`` RunUnprocessable, surfaced through
    the seam as ``AuthorError``) after the agent wrote some lesson bytes: no partial
    commit lands, the queue is NOT rotated (findings retryable), and — once the drain's
    rollback restores the corpus — a re-drain authors the finding EXACTLY once (no silent
    double-author).

    REVERSED BY #719: the leftover used to be load-bearing here, because the clean-scope
    gate refused the re-drain until something outside the drain discarded it — which is
    precisely how a retiring fault wedged its own channel. The drain now restores the
    corpus itself on a retiring fault, so the retry the attempt bump exists to allow
    actually happens."""
    a = tmp_repo.author
    helpers.write_finding(tmp_repo.paths.state_root / FINDINGS.queue, finding_id="run-P/0", run_id="run-P")
    commits_before = _commit_count(tmp_repo)

    def queued_ids() -> set[str]:
        return {r["finding_id"] for r in read_jsonl_rows(tmp_repo.paths.state_root / FINDINGS.queue)}

    def partial_then_raise(findings, batch_id, cfg):
        _write_lesson(tmp_repo, "half", "run-P/0")
        raise a.AuthorError("run_stage RunUnprocessable mid-batch")

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=partial_then_raise)) == 2
    assert _commit_count(tmp_repo) == commits_before
    assert queued_ids() == {"run-P/0"}
    assert not (tmp_repo.paths.state_root / FINDINGS.consumed).exists()

    assert tmp_repo.run_git("status", "--porcelain").stdout.strip() == "", (
        "the half-written lesson must be rolled back by the drain itself (#719)"
    )

    def succeed(findings, batch_id, cfg):
        _write_lesson(tmp_repo, "full", "run-P/0")
        return {"committed": ["run-P/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "defender: lesson full"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=succeed)) == 0
    assert _commit_count(tmp_repo) == commits_before + 1
    assert _head_files(tmp_repo) == ["defender/lessons/full.md"]
    assert (tmp_repo.paths.state_root / FINDINGS.queue).read_text().strip() == ""


def test_survival_committed_dirty_crosscheck(tmp_repo, helpers):
    """``verify_agent_state``'s committed⇔corpus-dirty cross-check still holds under the
    in-process invoke. BOTH inconsistent states abort (rc 2, queue intact):
    committed=[id] + CLEAN corpus, and committed=[] + DIRTY corpus. Positive control:
    the CONSISTENT state (committed=[id] + dirty corpus) commits and rotates out."""
    a = tmp_repo.author
    helpers.write_finding(tmp_repo.paths.state_root / FINDINGS.queue, finding_id="run-X/0", run_id="run-X")
    pre = _rows_without_attempts((tmp_repo.paths.state_root / FINDINGS.queue).read_text())

    def committed_but_clean(findings, batch_id, cfg):
        return {"committed": ["run-X/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "m"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=committed_but_clean)) == 2
    assert _rows_without_attempts((tmp_repo.paths.state_root / FINDINGS.queue).read_text()) == pre
    assert _attempts((tmp_repo.paths.state_root / FINDINGS.queue).read_text()) == [1] * len(pre)
    assert not (tmp_repo.paths.state_root / FINDINGS.consumed).exists()

    def dirty_but_no_commit(findings, batch_id, cfg):
        (tmp_repo.paths.lessons_dir / "orphan.md").write_text("uncommitted\n")
        return {"committed": [], "held_forward_bad": [],
                "consumed_skip": [{"finding_id": "run-X/0", "reason": "x"}],
                "commit_message": None}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=dirty_but_no_commit)) == 2
    assert _rows_without_attempts((tmp_repo.paths.state_root / FINDINGS.queue).read_text()) == pre
    # Second abort in the same test, so the lifetime count is at 2 — it does not reset
    # between ticks (#719).
    assert _attempts((tmp_repo.paths.state_root / FINDINGS.queue).read_text()) == [2] * len(pre)
    assert not (tmp_repo.paths.state_root / FINDINGS.consumed).exists()

    tmp_repo.run_git("reset", "--hard", "--quiet")
    tmp_repo.run_git("clean", "-fdq")

    def consistent(findings, batch_id, cfg):
        _write_lesson(tmp_repo, "ok", "run-X/0")
        return {"committed": ["run-X/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "defender: lesson ok"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=consistent)) == 0
    assert _head_files(tmp_repo) == ["defender/lessons/ok.md"]
    assert (tmp_repo.paths.state_root / FINDINGS.queue).read_text().strip() == ""


def test_survival_scope_gate_strays(tmp_repo, helpers):
    """The scope gate catches a NEW file the agent wrote OUTSIDE the corpus (→ AuthorError,
    rc 2), but a sibling's PRE-EXISTING baseline stray (staged before the agent ran) is
    NOT blamed on the curator. Positive control: with only the baseline stray, the batch
    commits the lesson (pathspec-scoped — the stray does not ride into the commit)."""
    a = tmp_repo.author
    helpers.write_finding(tmp_repo.paths.state_root / FINDINGS.queue, finding_id="run-S/0", run_id="run-S")
    pre = _rows_without_attempts((tmp_repo.paths.state_root / FINDINGS.queue).read_text())

    def writes_new_stray(findings, batch_id, cfg):
        (tmp_repo.root / "scratch.txt").write_text("oops")
        _write_lesson(tmp_repo, "in-scope", "run-S/0")
        return {"committed": ["run-S/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "defender: lesson in-scope"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=writes_new_stray)) == 2
    assert _rows_without_attempts((tmp_repo.paths.state_root / FINDINGS.queue).read_text()) == pre
    assert _attempts((tmp_repo.paths.state_root / FINDINGS.queue).read_text()) == [1] * len(pre)

    tmp_repo.run_git("reset", "--hard", "--quiet")
    tmp_repo.run_git("clean", "-fdq")
    (tmp_repo.root / "sibling_draft.md").write_text("unrelated staged work\n")
    tmp_repo.run_git("add", "sibling_draft.md")

    def writes_lesson_only(findings, batch_id, cfg):
        _write_lesson(tmp_repo, "in-scope", "run-S/0")
        return {"committed": ["run-S/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "defender: lesson in-scope"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=writes_lesson_only)) == 0
    head_files = _head_files(tmp_repo)
    assert head_files == ["defender/lessons/in-scope.md"]
    assert "sibling_draft.md" not in head_files
    assert (tmp_repo.paths.state_root / FINDINGS.queue).read_text().strip() == ""


def test_survival_idempotent_redrain(tmp_repo, helpers):
    """A re-drain of an already-committed batch does not double-commit or double-append:
    once the finding is cited in an existing lesson's ``source_finding_ids``, the next
    tick filters it (consumed_idempotent) and the agent is NEVER re-invoked. Positive
    control: tick 1 authored + committed the lesson exactly once."""
    a = tmp_repo.author
    helpers.write_finding(tmp_repo.paths.state_root / FINDINGS.queue, finding_id="run-I/0", run_id="run-I")
    commits_before = _commit_count(tmp_repo)

    def author_and_commit(findings, batch_id, cfg):
        _write_lesson(tmp_repo, "lessonI", "run-I/0")
        return {"committed": ["run-I/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "lessonI"}

    assert a.run_batch(hold_committed=True, cfg=replace(tmp_repo.cfg, invoke_agent=author_and_commit)) == 0
    assert _commit_count(tmp_repo) == commits_before + 1
    head_after_tick1 = tmp_repo.run_git("rev-parse", "HEAD").stdout.strip()
    assert "run-I/0" in (tmp_repo.paths.state_root / FINDINGS.queue).read_text()

    def must_not_author(findings, batch_id, cfg):
        raise AssertionError("re-authored an already-committed finding")

    assert a.run_batch(hold_committed=True, cfg=replace(tmp_repo.cfg, invoke_agent=must_not_author)) == 0
    assert tmp_repo.run_git("rev-parse", "HEAD").stdout.strip() == head_after_tick1
    assert (tmp_repo.paths.state_root / FINDINGS.queue).read_text().strip() == ""
    consumed = (tmp_repo.paths.state_root / FINDINGS.consumed).read_text()
    assert "run-I/0" in consumed
    assert "consumed_idempotent" in consumed


def test_survival_agent_no_git(tmp_repo, helpers):
    """The in-process agent runs NO git — the loop remains the SOLE committer. The agent
    leaves the lesson uncommitted in the working tree and the loop makes exactly ONE new,
    pathspec-scoped commit. If the agent held a git grant it would produce its own
    commit, so ``rev-list --count`` advancing by EXACTLY 1 (not ≥2) is the observable that
    the agent committed nothing."""
    a = tmp_repo.author
    helpers.write_finding(tmp_repo.paths.state_root / FINDINGS.queue, finding_id="run-G/0", run_id="run-G")
    commits_before = _commit_count(tmp_repo)

    def writes_lesson_no_git(findings, batch_id, cfg):
        _write_lesson(tmp_repo, "noGit", "run-G/0")
        return {"committed": ["run-G/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "defender: lesson noGit"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=writes_lesson_no_git)) == 0
    assert _commit_count(tmp_repo) == commits_before + 1
    assert _head_files(tmp_repo) == ["defender/lessons/noGit.md"]
    assert (tmp_repo.paths.state_root / FINDINGS.queue).read_text().strip() == ""


def _spawn_curator(**over):
    """Call the assumed ``curator_engine.run_curator_stage`` with hermetic defaults; a test
    overrides per case. Mirrors test_lead_author_engine.py's ``_spawn`` over
    ``run_author_stage``. The ``run_author`` DI seam captures the trace anchor without
    running the pydantic-ai graph. Signature per the SEAM INTERFACE CONTRACT (assumed)."""
    from defender.learning.author.curator_engine import (
        run_curator_stage,
    )

    # #773 M1: the curator spawn takes no forward-check group any more — the check is the
    # drain's, and what this test measures (one trace file per spawn) never depended on it.
    kw = dict(
        system_prompt_file=Path("/tmp/curator-prompt.md"),
        batch_id="batch-C",
        user_prompt="u",
        corpus_dir=Path("/tmp/wt/defender/lessons-environment"),
        repo_root=Path("/tmp/wt"),
        learning_run_dir=Path("/tmp/state/_pending"),
        model="glm-5.3",
        effort="low",
        request_limit=250,
        timeout=60,
        log=logging.getLogger("defender.test"),
        source_key=lambda model, label=None: None,
        run_author=lambda *a, **kw: "",
    )
    kw.update(over)
    return run_curator_stage(**as_curator_stage_args(kw))


def test_trace_per_spawn_distinct(tmp_path: Path):
    """UNIQUENESS at the composition frame: two curator spawns (C then D) in ONE drain,
    into ONE learning_run_dir, must get DISTINCT trace paths keyed on (batch_id, pid) — a
    single-spawn test cannot see the collision. Positive control (truncate-mode): opening
    a RequestLogger on one path truncates ONLY that path, so two DISTINCT names never
    clobber each other."""
    rd = tmp_path / "state" / "_pending"
    rd.mkdir(parents=True)

    seen: list[str] = []

    def _cap(wiring, ctx, **kw):
        seen.append(wiring.trace_name)
        return ""

    for bid in ("batch-C", "batch-D"):
        _spawn_curator(batch_id=bid, learning_run_dir=rd, run_author=_cap)

    assert len(set(seen)) == 2
    assert all(str(os.getpid()) in n for n in seen)
    assert any("batch-C" in n for n in seen)
    assert any("batch-D" in n for n in seen)

    from defender.runtime import observe

    c = rd / "batch-C.7.trace.jsonl"
    d = rd / "batch-D.7.trace.jsonl"
    c.write_text("C-TRACE\n")
    d.write_text("D-TRACE\n")
    observe.RequestLogger(d).close()
    assert d.read_text() == ""
    assert c.read_text() == "C-TRACE\n"


