"""Curator GLM port: the kept envelope survives (partial-write rollback, the scope gate), and
each spawn gets its own trace.

The survival rows run over a batch's git-free draft (the local `tmp_repo` fixture)."""
from __future__ import annotations

import logging
import os
from dataclasses import replace
from pathlib import Path


from defender.tests.support.learning.core._stage_args import as_curator_stage_args  # noqa: E402
import pytest

from defender._io import read_jsonl_rows
from defender.tests.support.learning.curation._author_draft import DraftRepo, attempts, rows_without_attempts


@pytest.fixture
def tmp_repo(tmp_path: Path):
    """The real lessons tick over a batch's git-free draft (`_curator1134.draft_lane`, config
    `draft_author_cfg`): `author`, `paths`, `cfg`, `state` and `lane`."""
    return DraftRepo.over(tmp_path)


def _commit_count(tmp_repo) -> int:
    """The commit-maker's commits on the batch branch."""
    return len(tmp_repo.lane.commits())


def _head_files(tmp_repo) -> list[str]:
    """The paths the batch branch's last commit changed."""
    lane = tmp_repo.lane
    return lane.git("show", "--name-only", "--pretty=format:", lane.tip()).stdout.split()


def test_survival_partial_write_rollback(tmp_repo, helpers):
    a = tmp_repo.author
    helpers.write_finding(tmp_repo.queue, finding_id="run-P/0", run_id="run-P")
    commits_before = _commit_count(tmp_repo)

    def queued_ids() -> set[str]:
        return {r["finding_id"] for r in read_jsonl_rows(tmp_repo.queue)}

    def partial_then_raise(findings, batch_id, cfg):
        tmp_repo.write_lesson("half", "run-P/0")
        raise a.AuthorError("run_stage RunUnprocessable mid-batch")

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=partial_then_raise)) == 2
    assert _commit_count(tmp_repo) == commits_before
    assert queued_ids() == {"run-P/0"}
    assert not tmp_repo.consumed.exists()

    assert tmp_repo.lane.drift() == [], "the drain left the half-written lesson in the draft"

    def succeed(findings, batch_id, cfg):
        tmp_repo.write_lesson("full", "run-P/0")
        return {"committed": ["run-P/0"], "consumed_skip": [],
                "commit_message": "defender: lesson full"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=succeed)) == 0
    assert _commit_count(tmp_repo) == commits_before + 1
    assert _head_files(tmp_repo) == ["agent/lessons/full.md"]
    assert tmp_repo.queue.read_text().strip() == ""


def test_survival_scope_gate_strays(tmp_repo, helpers):
    a = tmp_repo.author
    helpers.write_finding(tmp_repo.queue, finding_id="run-S/0", run_id="run-S")
    pre = rows_without_attempts(tmp_repo.queue.read_text())

    # The box writes only its lanes, so the stray sits in the drain's other lane, outside this
    # channel's corpus: the scope gate's case (a path outside every lane is a refused claim).
    def writes_new_stray(findings, batch_id, cfg):
        (tmp_repo.lane.sibling_dir / "scratch.txt").write_text("oops")
        tmp_repo.write_lesson("in-scope", "run-S/0")
        return {"committed": ["run-S/0"], "consumed_skip": [],
                "commit_message": "defender: lesson in-scope"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=writes_new_stray)) == 2
    assert rows_without_attempts(tmp_repo.queue.read_text()) == pre
    assert attempts(tmp_repo.queue.read_text()) == [1] * len(pre)

    assert tmp_repo.lane.drift() == [], "the refused tick left its stray in the draft"
    assert _commit_count(tmp_repo) == 0

    def writes_lesson_only(findings, batch_id, cfg):
        tmp_repo.write_lesson("in-scope", "run-S/0")
        return {"committed": ["run-S/0"], "consumed_skip": [],
                "commit_message": "defender: lesson in-scope"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=writes_lesson_only)) == 0
    assert _head_files(tmp_repo) == ["agent/lessons/in-scope.md"]
    assert tmp_repo.queue.read_text().strip() == ""


def _spawn_curator(**over):
    """``curator_engine.run_curator_stage`` with hermetic defaults; a test overrides per case."""
    from defender.learning.author.curator_engine import (
        run_curator_stage,
    )

    kw = dict(
        system_prompt_file=Path("/tmp/curator-prompt.md"),
        batch_id="batch-C",
        user_prompt="u",
        corpus_dir=Path("/tmp/wt/defender/lessons-questioner"),
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

    from defender.investigation import observe

    c = rd / "batch-C.7.trace.jsonl"
    d = rd / "batch-D.7.trace.jsonl"
    c.write_text("C-TRACE\n")
    d.write_text("D-TRACE\n")
    observe.RequestLogger(d).close()
    assert d.read_text() == ""
    assert c.read_text() == "C-TRACE\n"
