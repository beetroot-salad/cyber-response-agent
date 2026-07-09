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
import yaml

from defender._io import read_jsonl_rows
from defender.learning.author import curator, shared
from defender.learning.author.benign_actor import run as benign_run
from defender.learning.core.config import LoopPaths

# Workspace root (tests → defender → workspace), mirroring conftest.REAL_REPO — used
# to hand the state-root subprocess a PYTHONPATH that resolves ``defender.*``.
_WS_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Helpers (findings-author survival) — modeled on test_author_postflight.py
# ---------------------------------------------------------------------------


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


# ===========================================================================
# survival-partial-write-rollback  (R5 envelope; characterization)
# ===========================================================================


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
        _write_lesson(tmp_repo, "half", "run-P/0")  # partial write, no git
        raise a.AuthorError("run_stage RunUnprocessable mid-batch")

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=partial_then_raise)) == 2
    # no partial commit — HEAD did not advance
    assert _commit_count(tmp_repo) == commits_before
    # queue NOT rotated — the finding is retryable (its dead-letter attempts counter is bumped,
    # but it stays queued and is not committed/consumed)
    assert queued_ids() == {"run-P/0"}
    assert not tmp_repo.cfg.consumed_file.exists()

    # The leftover half.md sits UNCOMMITTED in the worktree; the clean-scope gate now
    # refuses a re-drain (dirty corpus → rc 2) — so the leftover is what the rollback
    # must clear before the finding can re-author.
    assert tmp_repo.run_git("status", "--porcelain").stdout.strip() != ""

    def succeed(findings, batch_id, cfg):
        _write_lesson(tmp_repo, "full", "run-P/0")
        return {"committed": ["run-P/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "defender: lesson full"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=succeed)) == 2  # blocked while dirty
    assert queued_ids() == {"run-P/0"}  # still retryable — the dirty-corpus pre-flight bailed before authoring

    # The drain's rollback — discard the worktree leftovers.
    tmp_repo.run_git("reset", "--hard", "--quiet")
    tmp_repo.run_git("clean", "-fdq")
    assert tmp_repo.run_git("status", "--porcelain").stdout.strip() == ""  # corpus git-clean

    # Re-drain authors the finding exactly ONCE (no double-author / no double-commit).
    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=succeed)) == 0
    assert _commit_count(tmp_repo) == commits_before + 1
    assert _head_files(tmp_repo) == ["defender/lessons/full.md"]
    assert tmp_repo.paths.pending_file.read_text().strip() == ""


# ===========================================================================
# survival-committed-dirty-crosscheck  (R5 envelope; characterization)
# ===========================================================================


def test_survival_committed_dirty_crosscheck(tmp_repo, helpers):
    """``verify_agent_state``'s committed⇔corpus-dirty cross-check still holds under the
    in-process invoke. BOTH inconsistent states abort (rc 2, queue intact):
    committed=[id] + CLEAN corpus, and committed=[] + DIRTY corpus. Positive control:
    the CONSISTENT state (committed=[id] + dirty corpus) commits and rotates out."""
    a = tmp_repo.author
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-X", "benign")
    helpers.write_finding(tmp_repo.paths.pending_file, finding_id="run-X/0", run_id="run-X")
    pre = tmp_repo.paths.pending_file.read_text()

    # committed=[id] but the agent wrote NOTHING (corpus clean) → AuthorError → rc 2.
    def committed_but_clean(findings, batch_id, cfg):
        return {"committed": ["run-X/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "m"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=committed_but_clean)) == 2
    assert tmp_repo.paths.pending_file.read_text() == pre
    assert not tmp_repo.cfg.consumed_file.exists()

    # committed=[] but the agent left corpus edits (dirty) → AuthorError → rc 2.
    def dirty_but_no_commit(findings, batch_id, cfg):
        (tmp_repo.paths.lessons_dir / "orphan.md").write_text("uncommitted\n")
        return {"committed": [], "held_forward_bad": [],
                "consumed_skip": [{"finding_id": "run-X/0", "reason": "x"}],
                "commit_message": None}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=dirty_but_no_commit)) == 2
    assert tmp_repo.paths.pending_file.read_text() == pre
    assert not tmp_repo.cfg.consumed_file.exists()

    # Clear the orphan edit, then the CONSISTENT state (committed=[id] + dirty) commits.
    tmp_repo.run_git("reset", "--hard", "--quiet")
    tmp_repo.run_git("clean", "-fdq")

    def consistent(findings, batch_id, cfg):
        _write_lesson(tmp_repo, "ok", "run-X/0")
        return {"committed": ["run-X/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "defender: lesson ok"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=consistent)) == 0
    assert _head_files(tmp_repo) == ["defender/lessons/ok.md"]
    assert tmp_repo.paths.pending_file.read_text().strip() == ""


# ===========================================================================
# survival-scope-gate-strays  (R5 envelope; characterization)
# ===========================================================================


def test_survival_scope_gate_strays(tmp_repo, helpers):
    """The scope gate catches a NEW file the agent wrote OUTSIDE the corpus (→ AuthorError,
    rc 2), but a sibling's PRE-EXISTING baseline stray (staged before the agent ran) is
    NOT blamed on the curator. Positive control: with only the baseline stray, the batch
    commits the lesson (pathspec-scoped — the stray does not ride into the commit)."""
    a = tmp_repo.author
    helpers.write_source_refs(tmp_repo.paths.runs_dir, "run-S", "benign")
    helpers.write_finding(tmp_repo.paths.pending_file, finding_id="run-S/0", run_id="run-S")
    pre = tmp_repo.paths.pending_file.read_text()

    # NEW stray outside defender/lessons/ (+ a valid lesson) → scope gate aborts.
    def writes_new_stray(findings, batch_id, cfg):
        (tmp_repo.root / "scratch.txt").write_text("oops")
        _write_lesson(tmp_repo, "in-scope", "run-S/0")
        return {"committed": ["run-S/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "defender: lesson in-scope"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=writes_new_stray)) == 2
    assert tmp_repo.paths.pending_file.read_text() == pre

    # Reset the failed batch's leftovers, then pre-stage a stray that exists BEFORE the
    # agent runs (a sibling curator's draft in the shared index) — the baseline.
    tmp_repo.run_git("reset", "--hard", "--quiet")
    tmp_repo.run_git("clean", "-fdq")
    (tmp_repo.root / "sibling_draft.md").write_text("unrelated staged work\n")
    tmp_repo.run_git("add", "sibling_draft.md")

    def writes_lesson_only(findings, batch_id, cfg):
        _write_lesson(tmp_repo, "in-scope", "run-S/0")  # no NEW stray
        return {"committed": ["run-S/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "defender: lesson in-scope"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=writes_lesson_only)) == 0
    head_files = _head_files(tmp_repo)
    assert head_files == ["defender/lessons/in-scope.md"]      # baseline stray not blamed
    assert "sibling_draft.md" not in head_files                # nor swept into the commit
    assert tmp_repo.paths.pending_file.read_text().strip() == ""


# ===========================================================================
# survival-idempotent-redrain  (R5 envelope; characterization)
# ===========================================================================


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

    # Tick 1 (drain): lesson committed, finding HELD (unmerged-PR semantics), stamp stripped.
    assert a.run_batch(hold_committed=True, cfg=replace(tmp_repo.cfg, invoke_agent=author_and_commit)) == 0
    assert _commit_count(tmp_repo) == commits_before + 1        # authored exactly once
    head_after_tick1 = tmp_repo.run_git("rev-parse", "HEAD").stdout.strip()
    assert "run-I/0" in tmp_repo.paths.pending_file.read_text()

    # Tick 2: the finding is now covered by the committed lesson → filtered as idempotent;
    # the agent is never re-invoked and no new commit lands.
    def must_not_author(findings, batch_id, cfg):
        raise AssertionError("re-authored an already-committed finding")

    assert a.run_batch(hold_committed=True, cfg=replace(tmp_repo.cfg, invoke_agent=must_not_author)) == 0
    assert tmp_repo.run_git("rev-parse", "HEAD").stdout.strip() == head_after_tick1  # no double-commit
    assert tmp_repo.paths.pending_file.read_text().strip() == ""
    consumed = tmp_repo.cfg.consumed_file.read_text()
    assert "run-I/0" in consumed
    assert "consumed_idempotent" in consumed


# ===========================================================================
# survival-agent-no-git  (R5 envelope; characterization)
# ===========================================================================


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
        _write_lesson(tmp_repo, "noGit", "run-G/0")  # writes a lesson, runs NO git
        return {"committed": ["run-G/0"], "held_forward_bad": [],
                "consumed_skip": [], "commit_message": "defender: lesson noGit"}

    assert a.run_batch(cfg=replace(tmp_repo.cfg, invoke_agent=writes_lesson_no_git)) == 0
    # loop is the sole committer: exactly one new commit (the agent contributed none)
    assert _commit_count(tmp_repo) == commits_before + 1
    # pathspec-scoped: the one commit touched only the corpus .md
    assert _head_files(tmp_repo) == ["defender/lessons/noGit.md"]
    assert tmp_repo.paths.pending_file.read_text().strip() == ""


# ===========================================================================
# env-corpus-two-writers-distinct  (R2 shared sink; characterization)
# ===========================================================================


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

    # Seed each direction's own queue (survived authors benign; caught authors adversarial).
    # source_run_dir="" sidesteps the held-out / bundle-missing gates (not under test here).
    ben.channel.file.write_text('{"observation_id": "eb/0", "judge_outcome": "survived", "source_run_dir": ""}\n')
    adv.channel.file.write_text('{"observation_id": "ea/0", "judge_outcome": "caught", "source_run_dir": ""}\n')

    # Serial drain: C then D, into the one shared corpus.
    assert curator.run_batch(hold_committed=False, cfg=ben) == 0
    assert curator.run_batch(hold_committed=False, cfg=adv) == 0

    # Distinct content on distinct paths in the shared corpus.
    corpus = repo / "defender" / "lessons-environment"
    assert (corpus / "lessonC.md").is_file()
    assert (corpus / "lessonD.md").is_file()

    # Distinct commit trailers per direction (each carries ITS label, not the sibling's).
    ben_msg = _commit_msg_for(repo, "defender/lessons-environment/lessonC.md")
    adv_msg = _commit_msg_for(repo, "defender/lessons-environment/lessonD.md")
    assert "Benign-Actor-Model:" in ben_msg
    assert "Actor-Env-Model:" not in ben_msg
    assert "Actor-Env-Model:" in adv_msg
    assert "Benign-Actor-Model:" not in adv_msg

    # Generation counters stay per-stream: each advanced by its OWN direction's commit only.
    assert shared.benign_generation_count(repo) == 2       # advanced by C, not D
    assert shared.actor_env_generation_count(repo) == 2    # advanced by D, not C


# ===========================================================================
# runner-teardown  (R5 removal/conservation; STRUCTURAL conservation guard)
# ===========================================================================


def test_runner_teardown_structural():
    """STRUCTURAL. No production module under ``defender/learning/author`` references the
    removed ``claude -p`` transport symbols — ``invoke_claude_print`` /
    ``curator_allowed_tools`` / ``curator_agent_env`` (all deleted) — while
    ``resolve_verifier_python`` SURVIVES with its four curator callers (each still builds a
    ``python3 <verifier>`` bash grant). AST-walk of Name/Attribute references (not
    docstrings/comments), so the check is about real callers — a conservation guard against
    re-introducing the transport."""
    import defender.learning.author.shared as _anchor  # any author module → the package dir

    author_dir = Path(_anchor.__file__).resolve().parent
    torn_down = ("invoke_claude_print", "curator_allowed_tools", "curator_agent_env")
    referencing = {sym: set() for sym in torn_down}
    verifier_callers: set[str] = set()

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
        if "resolve_verifier_python" in names:
            verifier_callers.add(rel)

    # Teardown: zero production references to the retired transport symbols.
    assert referencing["invoke_claude_print"] == set()
    assert referencing["curator_allowed_tools"] == set()
    assert referencing["curator_agent_env"] == set()

    # Survives: the four curators (A/B/C/D) each still resolve a verifier python.
    four_curators = {
        "lessons/run.py",             # A — findings → defender/lessons/
        "malicious_actor/run.py",     # B — actor tradecraft → defender/lessons-actor/
        "benign_actor/run.py",        # C — env benign → defender/lessons-environment/
        "benign_actor/env.py",        # D — env adversarial → defender/lessons-environment/
    }
    assert four_curators <= verifier_callers


# ===========================================================================
# Assumed port seam — the in-process curator stage (RED until built).
# Lazily imported so the characterization tests above still collect/run.
# ===========================================================================


def _spawn_curator(**over):
    """Call the assumed ``curator_engine.run_curator_stage`` with hermetic defaults; a test
    overrides per case. Mirrors test_lead_author_engine.py's ``_spawn`` over
    ``run_author_stage``. The ``run_author`` DI seam captures the trace anchor without
    running the pydantic-ai graph. Signature per the SEAM INTERFACE CONTRACT (assumed)."""
    from defender.learning.author.curator_engine import (  # port target — missing until implemented
        run_curator_stage,
    )

    kw = dict(
        system_prompt_file=Path("/tmp/curator-prompt.md"),
        batch_id="batch-C",
        user_prompt="u",
        corpus_dir=Path("/tmp/wt/defender/lessons-environment"),
        verifier_scripts=(),
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


# ===========================================================================
# trace-per-spawn-distinct  (R2 uniqueness at the composition frame; RED)
# ===========================================================================


def test_trace_per_spawn_distinct(tmp_path: Path):
    """UNIQUENESS at the composition frame: two curator spawns (C then D) in ONE drain,
    into ONE learning_run_dir, must get DISTINCT trace paths keyed on (batch_id, pid) — a
    single-spawn test cannot see the collision. Positive control (truncate-mode): opening
    a RequestLogger on one path truncates ONLY that path, so two DISTINCT names never
    clobber each other."""
    rd = tmp_path / "state" / "_pending"
    rd.mkdir(parents=True)

    # Two spawns in one drain → capture the trace_name each hands the transport.
    seen: list[str] = []

    def _cap(**kw):
        seen.append(kw["trace_name"])
        return ""

    for bid in ("batch-C", "batch-D"):
        _spawn_curator(batch_id=bid, learning_run_dir=rd, run_author=_cap)

    assert len(set(seen)) == 2                               # distinct per batch_id
    assert all(str(os.getpid()) in n for n in seen)          # pid keys concurrent drains
    assert any("batch-C" in n for n in seen)
    assert any("batch-D" in n for n in seen)

    # Positive control: RequestLogger opens in truncate mode (why distinct names matter).
    from defender.runtime import observe  # runtime extra — lazy so the survival tests don't need it

    c = rd / "batch-C.7.trace.jsonl"
    d = rd / "batch-D.7.trace.jsonl"
    c.write_text("C-TRACE\n")
    d.write_text("D-TRACE\n")
    observe.RequestLogger(d).close()          # opening d truncates ONLY d …
    assert d.read_text() == ""                # … truncate-mode confirmed …
    assert c.read_text() == "C-TRACE\n"       # … a DISTINCT path is untouched → no collision


# ===========================================================================
# trace-persistent-not-worktree  (R2; caller-anchor GREEN + stage-anchor RED)
# ===========================================================================


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

    # A batch worktree cfg: repo_root moves to the throwaway worktree, the state dir stays.
    paths = LoopPaths(repo_root=orig, state_dir=state).with_repo_root(worktree)
    cfg = benign_run.build_benign_config(paths)
    assert cfg.repo_root == worktree
    assert cfg.state_root == state
    assert cfg.pending_dir == state / "_pending"
    with pytest.raises(ValueError, match="subpath"):
        cfg.pending_dir.relative_to(worktree)     # persistent anchor NOT under the worktree

    # Stage anchor (RED): the trace lands under learning_run_dir, not repo_root.
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
    assert captured["anchor"] == rd               # anchored at the persistent dir …
    trace_path = captured["anchor"] / captured["name"]
    with pytest.raises(ValueError, match="subpath"):
        trace_path.relative_to(worktree)          # … so the trace is NOT under the worktree


# ===========================================================================
# forward-check-resolves-off-state-root  (deepest cross-file fault)
# ===========================================================================


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


def test_forward_check_resolves_off_state_root(tmp_path: Path):
    """The in-process forward-check resolves its source-case bundle off
    DEFENDER_LEARNING_STATE_DIR, not the throwaway worktree's empty ``runs/``. With the
    state root pinned into the agent's bash-tool env, a lesson's forward-check reads the
    REAL source case (positive control); WITHOUT the pin it resolves an empty/absent
    bundle and cannot see the case — the #425 silent-revert mode. The port's job is to
    ensure the var reaches this subprocess (the in-process twin of ``curator_agent_env``);
    this pins the resolution behavior it must preserve."""
    state = tmp_path / "state"
    run = state / "runs" / "run-X"
    run.mkdir(parents=True)
    (run / "investigation.md").write_text("TRANSCRIPT-BODY\n")
    (run / "source_refs.yaml").write_text(yaml.safe_dump({"normalized_disposition": "benign"}))
    worktree = tmp_path / "worktree"  # a fresh origin/main checkout: no runs/ of its own
    worktree.mkdir()

    snippet = (
        "from defender.learning.author.verify_forward import forward as vf;"
        "t, d = vf.load_run_context('run-X');"
        "print('RUNS_DIR', vf.RUNS_DIR);"
        "print('OK' if ('TRANSCRIPT-BODY' in t and d == 'benign') else 'MISS')"
    )

    # Positive: state root pinned → the forward-check reads the real source case.
    ppos = _run_forward_snippet(snippet, state_dir=state, cwd=worktree)
    assert ppos.returncode == 0, ppos.stderr
    assert str(state / "runs") in ppos.stdout
    assert "OK" in ppos.stdout

    # Negative: NO pin → the bundle resolves off the worktree/default, not the state root,
    # so the real case is unreachable (the silent-revert failure the pin prevents).
    pneg = _run_forward_snippet(snippet, state_dir=None, cwd=worktree)
    assert "OK" not in pneg.stdout
