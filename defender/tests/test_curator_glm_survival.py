"""Binding spec for the curator GLM port — envelope survival + trace/state-root/teardown.

One test per demand (spec_graph_curator-glm-port.yaml). Two kinds live here:

- CHARACTERIZATION (kept-envelope survival + env-corpus): these drive the REAL
  ``run_batch`` through the ``dataclasses.replace(cfg, invoke_agent=fake)`` seam
  (conftest.py's ``tmp_repo`` / the ``build_*_config`` factories) and assert the
  transaction envelope still rolls back / cross-checks / stays idempotent / keeps
  the loop the sole committer under the in-process invoke. Modeled on
  test_author_postflight.py / test_author_atomic.py / test_author_actor(_env).py.
  GREEN against HEAD (the envelope is unchanged by the port, R5).

- NEW behavior (trace uniqueness/persistence, state-root pin, runner teardown):
  these pin what the port ADDS and are RED until it lands. The two trace tests
  reach the assumed port seam ``defender.learning.author.curator_engine.run_curator_stage``
  (SEAM INTERFACE CONTRACT) via a LAZY import inside ``_spawn_curator`` so the
  characterization tests above still collect and run without the target present.

No ``monkeypatch.setattr`` — cfg-field + constructor injection only. Every negative
is paired with a positive control; expected values trace to the demand, not to a
re-implementation.
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from defender._io import read_jsonl_rows
from defender.learning.author import curator, shared
from defender.learning.author.benign_actor import run as benign_run
from defender.learning.core.config import LoopPaths

_WS_ROOT = Path(__file__).resolve().parents[2]




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
    rollback (``_discard_worktree_changes`` = ``git reset --hard`` + ``git clean``)
    restores the corpus — a re-drain authors the finding EXACTLY once (no silent
    double-author). The un-rolled-back leftover is load-bearing: the clean-scope gate
    refuses the re-drain until it is discarded."""
    a = tmp_repo.author
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-P", "benign")
    helpers.write_finding(tmp_repo.paths.pending_file, finding_id="run-P/0", run_id="run-P")
    commits_before = _commit_count(tmp_repo)

    def queued_ids() -> set[str]:
        return {r["finding_id"] for r in read_jsonl_rows(tmp_repo.paths.pending_file)}

    def partial_then_raise(findings, batch_id, cfg):
        _write_lesson(tmp_repo, "half", "run-P/0")
        raise a.AuthorError("run_stage RunUnprocessable mid-batch")

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=partial_then_raise)) == 2
    assert _commit_count(tmp_repo) == commits_before
    assert queued_ids() == {"run-P/0"}
    assert not tmp_repo.cfg.consumed_file.exists()

    assert tmp_repo.run_git("status", "--porcelain").stdout.strip() != ""

    def succeed(findings, batch_id, cfg):
        _write_lesson(tmp_repo, "full", "run-P/0")
        return {"committed": ["run-P/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "defender: lesson full"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=succeed)) == 2
    assert queued_ids() == {"run-P/0"}

    tmp_repo.run_git("reset", "--hard", "--quiet")
    tmp_repo.run_git("clean", "-fdq")
    assert tmp_repo.run_git("status", "--porcelain").stdout.strip() == ""

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=succeed)) == 0
    assert _commit_count(tmp_repo) == commits_before + 1
    assert _head_files(tmp_repo) == ["defender/lessons/full.md"]
    assert tmp_repo.paths.pending_file.read_text().strip() == ""




def test_survival_committed_dirty_crosscheck(tmp_repo, helpers):
    """``verify_agent_state``'s committed⇔corpus-dirty cross-check still holds under the
    in-process invoke. BOTH inconsistent states abort (rc 2, queue intact):
    committed=[id] + CLEAN corpus, and committed=[] + DIRTY corpus. Positive control:
    the CONSISTENT state (committed=[id] + dirty corpus) commits and rotates out."""
    a = tmp_repo.author
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-X", "benign")
    helpers.write_finding(tmp_repo.paths.pending_file, finding_id="run-X/0", run_id="run-X")
    pre = tmp_repo.paths.pending_file.read_text()

    def committed_but_clean(findings, batch_id, cfg):
        return {"committed": ["run-X/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "m"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=committed_but_clean)) == 2
    assert tmp_repo.paths.pending_file.read_text() == pre
    assert not tmp_repo.cfg.consumed_file.exists()

    def dirty_but_no_commit(findings, batch_id, cfg):
        (tmp_repo.paths.lessons_dir / "orphan.md").write_text("uncommitted\n")
        return {"committed": [], "held_forward_bad": [],
                "consumed_skip": [{"finding_id": "run-X/0", "reason": "x"}],
                "commit_message": None}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=dirty_but_no_commit)) == 2
    assert tmp_repo.paths.pending_file.read_text() == pre
    assert not tmp_repo.cfg.consumed_file.exists()

    tmp_repo.run_git("reset", "--hard", "--quiet")
    tmp_repo.run_git("clean", "-fdq")

    def consistent(findings, batch_id, cfg):
        _write_lesson(tmp_repo, "ok", "run-X/0")
        return {"committed": ["run-X/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "defender: lesson ok"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=consistent)) == 0
    assert _head_files(tmp_repo) == ["defender/lessons/ok.md"]
    assert tmp_repo.paths.pending_file.read_text().strip() == ""




def test_survival_scope_gate_strays(tmp_repo, helpers):
    """The scope gate catches a NEW file the agent wrote OUTSIDE the corpus (→ AuthorError,
    rc 2), but a sibling's PRE-EXISTING baseline stray (staged before the agent ran) is
    NOT blamed on the curator. Positive control: with only the baseline stray, the batch
    commits the lesson (pathspec-scoped — the stray does not ride into the commit)."""
    a = tmp_repo.author
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-S", "benign")
    helpers.write_finding(tmp_repo.paths.pending_file, finding_id="run-S/0", run_id="run-S")
    pre = tmp_repo.paths.pending_file.read_text()

    def writes_new_stray(findings, batch_id, cfg):
        (tmp_repo.root / "scratch.txt").write_text("oops")
        _write_lesson(tmp_repo, "in-scope", "run-S/0")
        return {"committed": ["run-S/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "defender: lesson in-scope"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=writes_new_stray)) == 2
    assert tmp_repo.paths.pending_file.read_text() == pre

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
    assert tmp_repo.paths.pending_file.read_text().strip() == ""




def test_survival_idempotent_redrain(tmp_repo, helpers):
    """A re-drain of an already-committed batch does not double-commit or double-append:
    once the finding is cited in an existing lesson's ``source_finding_ids``, the next
    tick filters it (consumed_idempotent) and the agent is NEVER re-invoked. Positive
    control: tick 1 authored + committed the lesson exactly once."""
    a = tmp_repo.author
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-I", "benign")
    helpers.write_finding(tmp_repo.paths.pending_file, finding_id="run-I/0", run_id="run-I")
    commits_before = _commit_count(tmp_repo)

    def author_and_commit(findings, batch_id, cfg):
        _write_lesson(tmp_repo, "lessonI", "run-I/0")
        return {"committed": ["run-I/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "lessonI"}

    assert a.run_batch(hold_committed=True, cfg=replace(tmp_repo.cfg, invoke_agent=author_and_commit)) == 0
    assert _commit_count(tmp_repo) == commits_before + 1
    head_after_tick1 = tmp_repo.run_git("rev-parse", "HEAD").stdout.strip()
    assert "run-I/0" in tmp_repo.paths.pending_file.read_text()

    def must_not_author(findings, batch_id, cfg):
        raise AssertionError("re-authored an already-committed finding")

    assert a.run_batch(hold_committed=True, cfg=replace(tmp_repo.cfg, invoke_agent=must_not_author)) == 0
    assert tmp_repo.run_git("rev-parse", "HEAD").stdout.strip() == head_after_tick1
    assert tmp_repo.paths.pending_file.read_text().strip() == ""
    consumed = tmp_repo.cfg.consumed_file.read_text()
    assert "run-I/0" in consumed
    assert "consumed_idempotent" in consumed




def test_survival_agent_no_git(tmp_repo, helpers):
    """The in-process agent runs NO git — the loop remains the SOLE committer. The agent
    leaves the lesson uncommitted in the working tree and the loop makes exactly ONE new,
    pathspec-scoped commit. If the agent held a git grant it would produce its own
    commit, so ``rev-list --count`` advancing by EXACTLY 1 (not ≥2) is the observable that
    the agent committed nothing."""
    a = tmp_repo.author
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-G", "benign")
    helpers.write_finding(tmp_repo.paths.pending_file, finding_id="run-G/0", run_id="run-G")
    commits_before = _commit_count(tmp_repo)

    def writes_lesson_no_git(findings, batch_id, cfg):
        _write_lesson(tmp_repo, "noGit", "run-G/0")
        return {"committed": ["run-G/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "defender: lesson noGit"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=writes_lesson_no_git)) == 0
    assert _commit_count(tmp_repo) == commits_before + 1
    assert _head_files(tmp_repo) == ["defender/lessons/noGit.md"]
    assert tmp_repo.paths.pending_file.read_text().strip() == ""




def _env_repo(tmp_path: Path):
    """A tmp git repo with the shared ``defender/lessons-environment/`` corpus + its
    pending dir — stands in for the layout both env directions (C benign, D adversarial)
    drain into. Returns the repo path."""
    repo = tmp_path / "repo"
    corpus = repo / "defender" / "lessons-environment"
    pending = repo / "defender" / "learning" / "_pending"
    corpus.mkdir(parents=True)
    pending.mkdir(parents=True)
    (corpus / ".gitkeep").write_text("")
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "seed"], check=True)
    return repo


def _commit_msg_for(repo: Path, rel_path: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "log", "-1", "--pretty=%B", "--", rel_path],
        capture_output=True, text=True, check=True,
    ).stdout


def test_env_corpus_two_writers_distinct(tmp_path: Path):
    """Curators C (benign) and D (adversarial) both write ``defender/lessons-environment/``
    but in separate, serialized batches. Their writes land on DISTINCT lesson paths, and
    their per-direction provenance trailers (Benign-Actor-Model: vs Actor-Env-Model:) and
    generation counters stay distinct — no cross-stream contamination on the shared sink."""
    repo = _env_repo(tmp_path)
    paths = LoopPaths(repo_root=repo)

    def _committing(name: str):
        def fake(observations, batch_id, cfg):
            oid = observations[0]["observation_id"]
            (cfg.corpus_dir / f"{name}.md").write_text(
                f"---\nsource_observation_ids: [{oid}]\n---\nbody {name}\n"
            )
            return {"committed": [oid], "consumed_skip": [], "commit_message": f"env lesson {name}"}
        return fake

    ben = replace(benign_run.build_benign_config(paths), invoke_agent=_committing("lessonC"))
    adv = replace(benign_run.build_adversarial_config(paths), invoke_agent=_committing("lessonD"))

    ben.channel.file.write_text('{"observation_id": "eb/0", "judge_outcome": "survived", "source_run_dir": ""}\n')
    adv.channel.file.write_text('{"observation_id": "ea/0", "judge_outcome": "caught", "source_run_dir": ""}\n')

    assert curator.run_batch(hold_committed=False, cfg=ben) == 0
    assert curator.run_batch(hold_committed=False, cfg=adv) == 0

    corpus = repo / "defender" / "lessons-environment"
    assert (corpus / "lessonC.md").is_file()
    assert (corpus / "lessonD.md").is_file()

    ben_msg = _commit_msg_for(repo, "defender/lessons-environment/lessonC.md")
    adv_msg = _commit_msg_for(repo, "defender/lessons-environment/lessonD.md")
    assert "Benign-Actor-Model:" in ben_msg
    assert "Actor-Env-Model:" not in ben_msg
    assert "Actor-Env-Model:" in adv_msg
    assert "Benign-Actor-Model:" not in adv_msg

    assert shared.benign_generation_count(repo) == 2
    assert shared.actor_env_generation_count(repo) == 2




def test_runner_teardown_structural():
    """STRUCTURAL. No production module under ``defender/learning/author`` references the
    removed ``claude -p`` transport symbols — ``invoke_claude_print`` /
    ``curator_allowed_tools`` / ``curator_agent_env`` (all deleted). AST-walk of Name/Attribute
    references (not docstrings/comments), so the check is about real callers — a conservation
    guard against re-introducing the transport.

    NB #558 INVERTS the old ``resolve_verifier_python`` SURVIVES assertion that used to live
    here (the forward-check is now an in-process tool, not a ``python3 <verifier>`` subprocess).
    That inversion is now owned by ``test_forward_check_tool.py::test_d26_no_curator_resolves_a
    _verifier_interpreter`` (demand d26 in spec_graph_558-forward-check-tool.yaml), which asserts
    ZERO callers — so it is dropped from this #556 teardown guard rather than kept green here."""
    import defender.learning.author.shared as _anchor

    author_dir = Path(_anchor.__file__).resolve().parent
    torn_down = ("invoke_claude_print", "curator_allowed_tools", "curator_agent_env")
    referencing = {sym: set() for sym in torn_down}

    for py in sorted(author_dir.rglob("*.py")):
        if py.name.startswith("test_"):
            continue
        names: set[str] = set()
        for node in ast.walk(ast.parse(py.read_text())):
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
        rel = py.relative_to(author_dir).as_posix()
        for sym in torn_down:
            if sym in names:
                referencing[sym].add(rel)

    assert referencing["invoke_claude_print"] == set()
    assert referencing["curator_allowed_tools"] == set()
    assert referencing["curator_agent_env"] == set()




def _spawn_curator(**over):
    """Call the assumed ``curator_engine.run_curator_stage`` with hermetic defaults; a test
    overrides per case. Mirrors test_lead_author_engine.py's ``_spawn`` over
    ``run_author_stage``. The ``run_author`` DI seam captures the trace anchor without
    running the pydantic-ai graph. Signature per the SEAM INTERFACE CONTRACT (assumed)."""
    from defender.learning.author.verify_forward.checks import ENV_CHECK as _ENV_CHECK
    from defender.learning.author.curator_engine import (
        run_curator_stage,
    )

    kw = dict(
        system_prompt_file=Path("/tmp/curator-prompt.md"),
        batch_id="batch-C",
        user_prompt="u",
        corpus_dir=Path("/tmp/wt/defender/lessons-environment"),
        check=_ENV_CHECK,
        runs_dir=Path("/tmp/state/runs"),
        pending=Path("/tmp/state/_pending/environment_observations.jsonl"),
        queued_ids=frozenset(),
        repo_root=Path("/tmp/wt"),
        learning_run_dir=Path("/tmp/state/_pending"),
        model="glm-5.2",
        effort="low",
        request_limit=250,
        timeout=60,
        log=lambda *a, **k: None,
        source_key=lambda model, label=None: None,
        run_author=lambda **kw: "",
    )
    kw.update(over)
    return run_curator_stage(**kw)




def test_trace_per_spawn_distinct(tmp_path: Path):
    """UNIQUENESS at the composition frame: two curator spawns (C then D) in ONE drain,
    into ONE learning_run_dir, must get DISTINCT trace paths keyed on (batch_id, pid) — a
    single-spawn test cannot see the collision. Positive control (truncate-mode): opening
    a RequestLogger on one path truncates ONLY that path, so two DISTINCT names never
    clobber each other."""
    rd = tmp_path / "state" / "_pending"
    rd.mkdir(parents=True)

    seen: list[str] = []

    def _cap(**kw):
        seen.append(kw["trace_name"])
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




def test_trace_persistent_not_worktree(tmp_path: Path):
    """The curator trace lands in PERSISTENT shared state (a pending/state dir), never the
    throwaway per-batch worktree, so it survives branch cleanup. Caller anchor (worktree
    cfg): the pending/state dir is worktree-immune (NOT under repo_root). Stage anchor:
    ``run_curator_stage`` writes the trace at the ``learning_run_dir`` it is handed (the
    persistent dir), not at ``repo_root``."""
    orig = tmp_path / "checkout"
    (orig / "defender" / "learning").mkdir(parents=True)
    state = tmp_path / "state"
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    paths = LoopPaths(repo_root=orig, state_dir=state).with_repo_root(worktree)
    cfg = benign_run.build_benign_config(paths)
    assert cfg.repo_root == worktree
    assert cfg.pending_dir == state / "_pending"
    with pytest.raises(ValueError, match="subpath"):
        cfg.pending_dir.relative_to(worktree)

    rd = state / "_pending"
    rd.mkdir(parents=True, exist_ok=True)
    captured: dict = {}

    def _cap(**kw):
        captured["anchor"] = kw["learning_run_dir"]
        captured["name"] = kw["trace_name"]
        return ""

    _spawn_curator(
        learning_run_dir=rd,
        repo_root=worktree,
        corpus_dir=worktree / "defender" / "lessons-environment",
        run_author=_cap,
    )
    assert captured["anchor"] == rd
    trace_path = captured["anchor"] / captured["name"]
    with pytest.raises(ValueError, match="subpath"):
        trace_path.relative_to(worktree)




def _run_forward_snippet(snippet: str, *, state_dir: Path | None, cwd: Path):
    """Run a forward-check snippet in a fresh subprocess (the verifiers freeze their paths
    from DEFAULT_PATHS at import, so the state root must be an ENV var). Mirrors
    test_verify_forward.py's ``_run_with_state``; ``state_dir=None`` leaves the var UNSET."""
    env = dict(os.environ)
    env.pop("DEFENDER_LEARNING_STATE_DIR", None)
    if state_dir is not None:
        env["DEFENDER_LEARNING_STATE_DIR"] = str(state_dir)
    env["PYTHONPATH"] = str(_WS_ROOT)
    return subprocess.run(
        [sys.executable, "-c", snippet],
        env=env, cwd=str(cwd), capture_output=True, text=True,
    )


