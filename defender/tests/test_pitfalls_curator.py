"""Pitfalls curation mode (Stage 2) — behavior spec at its own module seam.

Issue #513 (#455 Part 2) lifts the cross-run, threshold-gated ``execution.md``
pitfalls curation out of ``lead_author.py`` into ``leads/pitfalls_curator.py`` — a
**behavior-preserving module move**. These tests are the #511 characterization spec
for that mode, RELOCATED to bind at the new ``pitfalls_curator.*`` seam (the move is
clean, with no re-export shim on ``lead_author``). Against HEAD the target import
fails (the module doesn't exist yet) — the expected red before the move; after it the
whole file goes green. The assertions are byte-identical to the #511 spec that passed
against the equivalent ``lead_author.*`` seam, so green here means the moved behavior
is unchanged.

Borrowed collaborators are imported from their canonical homes — ``LeadAuthorError``
from ``lead_extraction``, ``persist`` / ``config`` / ``LoopPaths`` from ``core``, and
the runner from ``author.runner`` — NOT re-read off ``pitfalls_curator``. That keeps
this an independent encoding of intent and leaves the move free to source those
symbols however it likes (in particular, it does not force the new module to
re-export them). The shared spawn/verify/commit spine (#511's ``_spawn_author_agent``
/ ``_verify_corpus_scope`` / ``_loop_commit_body``) is invisible here: the tests bind
at the pitfalls seam, and the spawn capture patches the canonical runner module, so
this spec is agnostic to where that spine lands (issue #513 leaves it open).
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from defender.learning.leads import pitfalls_curator  # type: ignore[import-not-found]
from defender.learning.leads.lead_extraction import LeadAuthorError  # type: ignore[import-not-found]
from defender.learning.core import config, persist  # type: ignore[import-not-found]
from defender.learning.core.config import LoopPaths  # type: ignore[import-not-found]


# ---------------------------------------------------------------------------
# Seeded-worktree fixture — a clean git repo standing in for a fresh
# ``lead-author/<id>`` worktree (the curator runs no git; the loop commits).
# ---------------------------------------------------------------------------


def _run_git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd,
                          capture_output=True, text=True, check=True)


@pytest.fixture
def tmp_git_repo(tmp_path: Path) -> Path:
    """A clean git repo with a seeded skills tree (committed) — stands in for a fresh
    ``lead-author/<id>`` worktree. The curator runs no git, so tests then make
    *working-tree* edits and call ``_verify_pitfalls_state`` / drive ``run_pitfalls``
    over them, asserting the loop's gate + commit behavior."""
    repo = tmp_path / "repo"
    catalog = repo / "defender" / "skills" / "gather" / "queries"
    (catalog / "wazuh" / "_draft").mkdir(parents=True)
    (catalog / "SCHEMA.md").write_text("# template schema\n")
    (catalog / "wazuh" / "auth-events.md").write_text(
        "---\nid: wazuh.auth-events\nstatus: established\n---\n"
    )
    (catalog / "wazuh" / "_draft" / "newthing.md").write_text(
        "---\nid: wazuh.newthing\nstatus: draft\n---\n"
    )
    skill = repo / "defender" / "skills" / "elastic"
    (skill / "_draft").mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: defender-elastic\n---\n# elastic\n")
    (skill / "_draft" / "README.md").write_text("# surface declaration\n")
    (skill / "_draft" / "falco-na.md").write_text(
        "---\nid: elastic.falco-na\nstatus: draft\n---\n# pending\n"
    )
    _run_git(repo, "init", "-q", "-b", "main")
    _run_git(repo, "config", "user.email", "test@example.com")
    _run_git(repo, "config", "user.name", "Test")
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "seed")
    return repo


# ---------------------------------------------------------------------------
# _verify_pitfalls_state — the loop-side scope gate over the curator's edits.
# Its ONLY permitted in-corpus change is an edit to a system ``execution.md``.
# ---------------------------------------------------------------------------


def test_verify_pitfalls_state_accepts_execution_md(tmp_git_repo: Path):
    (tmp_git_repo / "defender" / "skills" / "elastic" / "execution.md").write_text(
        "# elastic\n## Common pitfalls\n- use `index=windows`, not `index:windows`\n"
    )
    changed = pitfalls_curator._verify_pitfalls_state(tmp_git_repo, baseline_stray=[])
    assert changed == ["defender/skills/elastic/execution.md"]


def test_verify_pitfalls_state_rejects_non_execution_md(tmp_git_repo: Path):
    """A SKILL.md edit is in lead-author scope but NOT pitfalls scope — rejected."""
    skill = tmp_git_repo / "defender" / "skills" / "elastic" / "SKILL.md"
    skill.write_text(skill.read_text() + "\nedit\n")
    with pytest.raises(LeadAuthorError, match="non-execution.md"):
        pitfalls_curator._verify_pitfalls_state(tmp_git_repo, baseline_stray=[])


def test_verify_pitfalls_state_rejects_stray(tmp_git_repo: Path):
    (tmp_git_repo / "defender" / "other").mkdir(parents=True)
    (tmp_git_repo / "defender" / "other" / "stray.md").write_text("x")
    with pytest.raises(LeadAuthorError, match="outside"):
        pitfalls_curator._verify_pitfalls_state(tmp_git_repo, baseline_stray=[])


def test_verify_pitfalls_state_rejects_deletion(tmp_git_repo: Path):
    ex = tmp_git_repo / "defender" / "skills" / "elastic" / "execution.md"
    ex.write_text("# e\n")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "add exec")
    ex.unlink()
    with pytest.raises(LeadAuthorError, match="deleted"):
        pitfalls_curator._verify_pitfalls_state(tmp_git_repo, baseline_stray=[])


def test_verify_pitfalls_stray_wins_over_in_corpus_violation(tmp_git_repo: Path):
    """A stray edit AND an in-corpus non-execution.md edit → the stray-gate error
    ('outside') is raised, not the 'non-execution.md' loop error — proving the shared
    preamble runs before the per-path loop."""
    (tmp_git_repo / "defender" / "other").mkdir(parents=True)
    (tmp_git_repo / "defender" / "other" / "stray.md").write_text("stray")
    skill = tmp_git_repo / "defender" / "skills" / "elastic" / "SKILL.md"
    skill.write_text(skill.read_text() + "\nedit\n")  # in-corpus, non-execution.md
    with pytest.raises(LeadAuthorError, match="outside"):
        pitfalls_curator._verify_pitfalls_state(tmp_git_repo, baseline_stray=[])


def test_verify_pitfalls_state_returns_sorted_changed(tmp_git_repo: Path):
    """Two execution.md edits that interleave across git's status-class boundary → the
    returned list is sorted, discriminating `return sorted(changed)`: a tracked-modified
    `elastic/execution.md` (changed class, sorts LATE) is listed by git BEFORE an
    untracked `cmdb/execution.md` (untracked class, sorts EARLY), so only `sorted()`
    yields [cmdb, elastic]. A regression to `return changed` returns [elastic, cmdb]."""
    # Commit elastic/execution.md so its later edit lands in the changed class.
    (tmp_git_repo / "defender" / "skills" / "elastic" / "execution.md").write_text("# e\n")
    _run_git(tmp_git_repo, "add", "defender/skills/elastic/execution.md")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "seed execution.md")
    (tmp_git_repo / "defender" / "skills" / "elastic" / "execution.md").write_text(
        "# e edited\n"  # tracked, modified → " M" (sorts LATE)
    )
    (tmp_git_repo / "defender" / "skills" / "cmdb").mkdir(parents=True)
    (tmp_git_repo / "defender" / "skills" / "cmdb" / "execution.md").write_text(
        "# c\n"  # untracked → "??" (sorts EARLY)
    )
    changed = pitfalls_curator._verify_pitfalls_state(tmp_git_repo, baseline_stray=[])
    assert changed == [
        "defender/skills/cmdb/execution.md",
        "defender/skills/elastic/execution.md",
    ]


# ---------------------------------------------------------------------------
# run_pitfalls — cross-run, threshold-gated entry point. Below threshold it is a
# no-op with the queue intact; at threshold it spawns (injectable), verifies,
# commits pathspec-scoped, and rotates the batch out of the central queue.
# ---------------------------------------------------------------------------


def _seed_pitfalls(paths, n: int) -> None:
    persist.append_pitfalls(
        [
            {
                "schema_version": 1, "pitfall_id": f"r:l-{i:03d}:0", "source_run": "r",
                "system": "elastic", "query_id": "elastic.esql", "goal": "g",
                "executed_query": "bad pipe", "stderr_digest": "exit=1; mismatched input",
                "error_class": "agent-fixable",
            }
            for i in range(n)
        ],
        paths=paths,
    )


def test_run_pitfalls_below_threshold_is_noop(tmp_git_repo: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "5")
    paths = LoopPaths(repo_root=tmp_git_repo, state_dir=tmp_path / "state")
    _seed_pitfalls(paths, 2)
    called = []
    rc = pitfalls_curator.run_pitfalls(paths=paths, invoke=lambda *a, **k: called.append(1) or 0)
    assert rc == 0
    assert called == []                                   # no spawn
    assert len(persist.read_pitfalls(paths)) == 2         # queue intact


def test_run_pitfalls_at_threshold_commits_and_rotates(tmp_git_repo: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    paths = LoopPaths(repo_root=tmp_git_repo, state_dir=tmp_path / "state")
    _seed_pitfalls(paths, 2)

    def fake_invoke(handoffs, *, repo_root):
        # one handoff for `elastic`, carrying both failures
        assert handoffs[0]["system"] == "elastic"
        assert handoffs[0]["execution_md_path"] == "defender/skills/elastic/execution.md"
        assert len(handoffs[0]["failures"]) == 2
        p = repo_root / "defender" / "skills" / "elastic" / "execution.md"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("# elastic\n## Common pitfalls\n- use `index=windows`, not `index:windows`\n")
        return 0

    rc = pitfalls_curator.run_pitfalls(paths=paths, invoke=fake_invoke)
    assert rc == 0
    # committed to defender/skills/ in the worktree
    log = _run_git(tmp_git_repo, "log", "--oneline", "-1").stdout
    assert "execution.md pitfalls" in log
    # queue drained, consumed file records the batch
    assert persist.read_pitfalls(paths) == []
    consumed = [json.loads(ln) for ln in paths.pitfalls.consumed.read_text().splitlines()]
    assert {c["pitfall_id"] for c in consumed} == {"r:l-000:0", "r:l-001:0"}


def test_run_pitfalls_no_edit_tick_still_rotates(tmp_git_repo: Path, tmp_path: Path, monkeypatch):
    """A curator that legitimately makes no edits (every failure already documented
    / too thin to fix — a valid tick per the prompt) must still drain the batch.
    Otherwise the queue stays >= threshold and re-spawns the curator forever."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    paths = LoopPaths(repo_root=tmp_git_repo, state_dir=tmp_path / "state")
    _seed_pitfalls(paths, 2)
    rc = pitfalls_curator.run_pitfalls(paths=paths, invoke=lambda handoffs, *, repo_root: 0)
    assert rc == 0
    assert persist.read_pitfalls(paths) == []                            # drained, not stuck
    assert _run_git(tmp_git_repo, "status", "--porcelain").stdout == ""  # no commit/edits


def test_run_pitfalls_all_systemless_drops_batch_without_spawn(tmp_git_repo: Path, tmp_path: Path, monkeypatch):
    """A batch whose rows all carry no system can't be folded into any execution.md;
    run_pitfalls drops it without spawning the curator instead of leaving it stuck at
    threshold and re-waking the drain every tick."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    paths = LoopPaths(repo_root=tmp_git_repo, state_dir=tmp_path / "state")
    persist.append_pitfalls(
        [{"pitfall_id": f"r:{i}", "system": ""} for i in range(2)], paths=paths
    )
    called: list[int] = []
    rc = pitfalls_curator.run_pitfalls(paths=paths, invoke=lambda *a, **k: called.append(1) or 0)
    assert rc == 0
    assert called == []                                   # no curator spawn
    assert persist.read_pitfalls(paths) == []             # dropped, not stuck


# ---------------------------------------------------------------------------
# _invoke_pitfalls_agent — the real spawn wiring. run_pitfalls injects a fake
# invoke, so this body is otherwise never exercised; capture the RunnerOptions +
# user_prompt at the shared runner seam (the mode has no DI seam for the spawn).
# ---------------------------------------------------------------------------


def _capture_engine(monkeypatch, *, rc: int = 0, raise_exc=None):
    """Patch the in-process engine seam the shared spawn spine calls (the GLM port replaced the
    ``invoke_claude_print_raw`` capture). ``_spawn_author_agent`` looks up ``run_author_stage`` on
    the engine module at call time, so patching the module attr is seen regardless of where the
    spine lands. Captures the kwargs the pitfalls spawn forwards + returns a canned rc / raises."""
    from defender.learning.leads import lead_author_engine  # the port target

    cap: dict = {}

    def _fake(**kwargs):
        cap.update(kwargs)
        if raise_exc is not None:
            raise raise_exc
        return rc

    monkeypatch.setattr(  # lint-monkeypatch: ok — the shared spawn spine has no DI seam
        lead_author_engine, "run_author_stage", _fake
    )
    return cap


def test_invoke_pitfalls_agent_prompt_reaches_engine(tmp_path: Path, monkeypatch):
    """The pitfalls prompt (skills_dir + pitfalls_handoffs, and NONE of the per-run keys) reaches
    the in-process engine as the ``user_prompt`` payload."""
    cap = _capture_engine(monkeypatch)
    handoffs = [{"system": "elastic",
                 "execution_md_path": "defender/skills/elastic/execution.md",
                 "failures": []}]
    rc = pitfalls_curator._invoke_pitfalls_agent(handoffs, repo_root=tmp_path)
    assert rc == 0
    prompt = cap["user_prompt"]
    assert "pitfalls_handoffs (1)" in prompt
    assert "skills_dir: defender/skills/" in prompt
    assert "run_dir" not in prompt
    assert "catalog_dir" not in prompt
    assert "executed_template_handoffs" not in prompt


def test_invoke_pitfalls_agent_wires_engine_kwargs_and_pending_anchor(tmp_path: Path, monkeypatch):
    """(rewrite of the RunnerOptions/allowlist-string options-wiring — both are gone) The engine
    gets the pitfalls prompt, the 'pitfalls' batch id, and the injected repo_root. F4: the pitfalls
    curator has NO per-run dir, so its learning trace anchors at PENDING_DIR (the stable cross-run
    queue dir), not a synthesized run dir. Model/effort/request_limit default inside
    run_author_stage (pinned in test_lead_author_engine)."""
    cap = _capture_engine(monkeypatch)
    pitfalls_curator._invoke_pitfalls_agent([], repo_root=tmp_path)
    assert cap["system_prompt_file"] == pitfalls_curator.LEAD_PITFALLS_PROMPT
    assert cap["batch_id"] == "pitfalls"
    assert cap["repo_root"] == tmp_path
    assert cap["learning_run_dir"] == config.DEFAULT_PATHS.lead_pending_dir


def test_invoke_pitfalls_agent_config_fault_propagates(tmp_path: Path, monkeypatch):
    """F1: a systemic config fault from the engine PROPAGATES through the pitfalls spawn too —
    not swallowed into an rc."""
    from defender.learning.core.config import FatalConfigError
    _capture_engine(monkeypatch, raise_exc=FatalConfigError("needs FIREWORKS_API_KEY"))
    with pytest.raises(FatalConfigError):
        pitfalls_curator._invoke_pitfalls_agent([], repo_root=tmp_path)


def test_invoke_pitfalls_agent_passes_through_engine_rc(tmp_path: Path, monkeypatch):
    """A per-run rc (124 from a RunUnprocessable inside the engine) is returned unchanged."""
    _capture_engine(monkeypatch, rc=124)
    assert pitfalls_curator._invoke_pitfalls_agent([], repo_root=tmp_path) == 124


# ---------------------------------------------------------------------------
# _pitfalls_commit_message — the deterministic loop-authored message (fixed title).
# Pure function; asserted by structural substring, pinning the byte structure.
# ---------------------------------------------------------------------------


def test_pitfalls_commit_message_title_and_body():
    """Fixed 'execution.md pitfalls' title; body lists each changed path as '- {p}'."""
    msg = pitfalls_curator._pitfalls_commit_message(
        ["defender/skills/elastic/execution.md", "defender/skills/cmdb/execution.md"]
    )
    assert "learning(lead-author): execution.md pitfalls" in msg
    # Pin the summary→Paths `\n\n`, the inter-path `\n` join, and the trailing `\n` — the
    # per-path substrings alone would still pass if a joining newline were dropped.
    assert (
        "git).\n\n"
        "Paths:\n"
        "- defender/skills/elastic/execution.md\n"
        "- defender/skills/cmdb/execution.md\n"
    ) in msg
