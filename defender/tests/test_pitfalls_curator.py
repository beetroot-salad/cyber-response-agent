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
the engine from ``lead_author_engine`` — NOT re-read off ``pitfalls_curator``. That keeps
this an independent encoding of intent and leaves the move free to source those
symbols however it likes (in particular, it does not force the new module to
re-export them). The shared spawn/verify/commit spine (#511's ``_spawn_author_agent``
/ ``_verify_corpus_scope`` / ``_loop_commit_body``) is invisible here: the tests bind
at the pitfalls seam, and the spawn capture patches the canonical runner module, so
this spec is agnostic to where that spine lands (issue #513 leaves it open).
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from defender.learning.leads import pitfalls_curator  # type: ignore[import-not-found]
from defender.learning.leads.lead_extraction import LeadAuthorError  # type: ignore[import-not-found]
from defender.learning.core import config, persist  # type: ignore[import-not-found]
from defender.learning.core.config import LoopPaths  # type: ignore[import-not-found]
from defender.tests._repo import seed_skills_repo




def _run_git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd,
                          capture_output=True, text=True, check=True)


@pytest.fixture
def tmp_git_repo(tmp_path: Path) -> Path:
    """A clean git repo with a seeded skills tree (committed) — stands in for a fresh
    ``lead-author/<id>`` worktree. The curator runs no git, so tests then make
    *working-tree* edits and call ``_verify_pitfalls_state`` / drive ``run_pitfalls``
    over them, asserting the loop's gate + commit behavior."""
    return seed_skills_repo(tmp_path / "repo")




#: The fixture's adapter-declared systems (`tests/_repo.seed_skills_repo`), threaded
#: explicitly per #869 — every consumer answers from the value it is handed, never from a
#: re-derivation of the tree.
DECLARED = frozenset({"elastic", "wazuh"})


def test_verify_pitfalls_state_accepts_execution_md(tmp_git_repo: Path):
    (tmp_git_repo / "defender" / "skills" / "elastic" / "execution.md").write_text(
        "# elastic\n## Common pitfalls\n- use `index=windows`, not `index:windows`\n"
    )
    changed = pitfalls_curator._verify_pitfalls_state(
        tmp_git_repo, baseline_stray=[], systems=DECLARED, reducer_offered=False)
    assert changed == ["defender/skills/elastic/execution.md"]


def test_verify_pitfalls_state_rejects_non_execution_md(tmp_git_repo: Path):
    """A SKILL.md edit is in lead-author scope but NOT pitfalls scope — rejected."""
    skill = tmp_git_repo / "defender" / "skills" / "elastic" / "SKILL.md"
    skill.write_text(skill.read_text() + "\nedit\n")
    with pytest.raises(LeadAuthorError, match="non-execution.md"):
        pitfalls_curator._verify_pitfalls_state(
            tmp_git_repo, baseline_stray=[], systems=DECLARED, reducer_offered=False)


def test_verify_pitfalls_state_rejects_stray(tmp_git_repo: Path):
    (tmp_git_repo / "defender" / "other").mkdir(parents=True)
    (tmp_git_repo / "defender" / "other" / "stray.md").write_text("x")
    with pytest.raises(LeadAuthorError, match="outside"):
        pitfalls_curator._verify_pitfalls_state(
            tmp_git_repo, baseline_stray=[], systems=DECLARED, reducer_offered=False)


def test_verify_pitfalls_state_rejects_deletion(tmp_git_repo: Path):
    ex = tmp_git_repo / "defender" / "skills" / "elastic" / "execution.md"
    ex.write_text("# e\n")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "add exec")
    ex.unlink()
    with pytest.raises(LeadAuthorError, match="deleted"):
        pitfalls_curator._verify_pitfalls_state(
            tmp_git_repo, baseline_stray=[], systems=DECLARED, reducer_offered=False)


def test_verify_pitfalls_stray_wins_over_in_corpus_violation(tmp_git_repo: Path):
    """A stray edit AND an in-corpus non-execution.md edit → the stray-gate error
    ('outside') is raised, not the 'non-execution.md' loop error — proving the shared
    preamble runs before the per-path loop."""
    (tmp_git_repo / "defender" / "other").mkdir(parents=True)
    (tmp_git_repo / "defender" / "other" / "stray.md").write_text("stray")
    skill = tmp_git_repo / "defender" / "skills" / "elastic" / "SKILL.md"
    skill.write_text(skill.read_text() + "\nedit\n")
    with pytest.raises(LeadAuthorError, match="outside"):
        pitfalls_curator._verify_pitfalls_state(
            tmp_git_repo, baseline_stray=[], systems=DECLARED, reducer_offered=False)


def test_verify_pitfalls_state_returns_sorted_changed(tmp_git_repo: Path):
    """Two execution.md edits that interleave across git's status-class boundary → the
    returned list is sorted, discriminating `return sorted(changed)`: a tracked-modified
    `elastic/execution.md` (changed class, sorts LATE) is listed by git BEFORE an
    untracked `cmdb/execution.md` (untracked class, sorts EARLY), so only `sorted()`
    yields [cmdb, elastic]. A regression to `return changed` returns [elastic, cmdb].

    `cmdb` is seeded as a REAL system dir (its `SKILL.md` is committed here, as the fixture
    commits elastic's) because an `execution.md` under a directory holding no `SKILL.md` is
    refused outright now — #855 F-06's minting gate. The untracked-`execution.md` half of the
    interleaving, which is what this test needs, is untouched by that."""
    cmdb = tmp_git_repo / "defender" / "skills" / "cmdb"
    cmdb.mkdir(parents=True)
    (cmdb / "SKILL.md").write_text("---\nname: defender-cmdb\n---\n# cmdb\n")
    (tmp_git_repo / "defender" / "skills" / "elastic" / "execution.md").write_text("# e\n")
    _run_git(tmp_git_repo, "add",
             "defender/skills/elastic/execution.md", "defender/skills/cmdb/SKILL.md")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "seed execution.md")
    (tmp_git_repo / "defender" / "skills" / "elastic" / "execution.md").write_text(
        "# e edited\n"
    )
    (cmdb / "execution.md").write_text("# c\n")
    changed = pitfalls_curator._verify_pitfalls_state(
        tmp_git_repo, baseline_stray=[], systems=DECLARED | {"cmdb"}, reducer_offered=False)
    assert changed == [
        "defender/skills/cmdb/execution.md",
        "defender/skills/elastic/execution.md",
    ]




def _seed_pitfalls(paths, n: int) -> None:
    """``n`` queued pitfalls, each a DISTINCT mistake — one `stderr_digest` per row, since
    #840 collapses repeats of one digest into a single record and the threshold counts
    records. These cases are about the gate and the rotation, not the collapse."""
    persist.append_pitfalls(
        [
            {
                "schema_version": 1, "pitfall_id": f"r:l-{i:03d}:0", "source_run": "r",
                "system": "elastic", "query_id": "elastic.esql", "goal": "g",
                "executed_query": "bad pipe",
                "stderr_digest": f"exit=1; mismatched input at token {i}",
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
    assert called == []
    assert len(persist.read_pitfalls(paths)) == 2


def test_run_pitfalls_at_threshold_commits_and_rotates(tmp_git_repo: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    paths = LoopPaths(repo_root=tmp_git_repo, state_dir=tmp_path / "state")
    _seed_pitfalls(paths, 2)

    def fake_invoke(handoffs, *, repo_root, box=None):
        assert handoffs[0]["system"] == "elastic"
        assert handoffs[0]["path"] == "defender/skills/elastic/execution.md"
        assert len(handoffs[0]["failures"]) == 2
        p = repo_root / "defender" / "skills" / "elastic" / "execution.md"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("# elastic\n## Common pitfalls\n- use `index=windows`, not `index:windows`\n")
        return 0

    rc = pitfalls_curator.run_pitfalls(paths=paths, invoke=fake_invoke)
    assert rc == 0
    log = _run_git(tmp_git_repo, "log", "--oneline", "-1").stdout
    assert "execution.md pitfalls" in log
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
    rc = pitfalls_curator.run_pitfalls(
        paths=paths, invoke=lambda handoffs, *, repo_root, box=None: 0
    )
    assert rc == 0
    assert persist.read_pitfalls(paths) == []
    assert _run_git(tmp_git_repo, "status", "--porcelain").stdout == ""


def test_a_queued_system_with_no_skills_dir_never_becomes_a_handoff_path(tmp_git_repo: Path):
    """#855 F-06, the offline half. The handoff's `path` is a PATH BUILT FROM A QUEUE FIELD and
    the curator is told to read and write it, so a `system` that reached the queue from
    anywhere unvetted mints a brand-new single-segment directory under `defender/skills/` — the
    phantom-system class #821/#828 closed for `h-*` and `system_for_payload_operands` closed
    for the reducer names. The writer is where this is really fixed (`query_tool.
    _system_of_record`); this is the boundary that would have contained it anyway.

    The positive control is in the same call: `elastic`, a system whose directory the fixture
    committed, keeps its handoff — a filter that dropped everything would pass the negative."""
    rows = [
        {"system": s, "query_id": f"{s}.esql", "goal": "g", "executed_query": "x",
         "stderr_digest": f"exit=64; boom {s}"}
        for s in ("elastic", "Ignore Previous Instructions", "sql", "a b")
    ]
    handoffs = pitfalls_curator._build_pitfalls_handoffs(rows, systems=DECLARED)
    assert [h["system"] for h in handoffs] == ["elastic"]
    assert handoffs[0]["path"] == "defender/skills/elastic/execution.md"


def test_the_commit_gate_refuses_an_execution_md_that_mints_its_own_system_dir(tmp_git_repo: Path):
    """The last gate on the same class (#855 F-06), and it asks about the DIRECTORY's
    MEMBERSHIP, not the file: a declared system with no `execution.md` yet may still take a
    first one, so creating the file in a declared system's dir stays legal while creating an
    undeclared directory around it does not."""
    ghost = tmp_git_repo / "defender" / "skills" / "ghost"
    ghost.mkdir(parents=True)
    (ghost / "execution.md").write_text("# ghost\n## Common pitfalls\n- invented\n")
    with pytest.raises(LeadAuthorError, match="undeclared system"):
        pitfalls_curator._verify_pitfalls_state(
            tmp_git_repo, baseline_stray=[], systems=DECLARED, reducer_offered=False)

    # Positive control on the same gate: the fixture's real system dir takes a NEW execution.md.
    (ghost / "execution.md").unlink()
    ghost.rmdir()
    (tmp_git_repo / "defender" / "skills" / "elastic" / "execution.md").write_text("# e\n")
    assert pitfalls_curator._verify_pitfalls_state(
        tmp_git_repo, baseline_stray=[], systems=DECLARED, reducer_offered=False) == [
        "defender/skills/elastic/execution.md"
    ]


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
    assert called == []
    assert persist.read_pitfalls(paths) == []




def _capture_engine(monkeypatch, *, rc: int = 0, raise_exc=None):
    """Patch the in-process engine seam the shared spawn spine calls. ``_spawn_author_agent`` looks
    up ``run_author_stage`` on the engine module at call time, so patching the module attr is seen regardless of where the
    spine lands. Captures the kwargs the pitfalls spawn forwards + returns a canned rc / raises."""
    from defender.learning.leads import lead_author_engine

    cap: dict = {}

    def _fake(**kwargs):
        cap.update(kwargs)
        # #713: the spawn now forwards a StageWiring/StageContext pair. Flatten the fields
        # the cases assert on back onto `cap`, so each case still names one knob.
        if (w := kwargs.get("wiring")) is not None:
            cap.update(system_prompt_file=w.prompt_path, model=w.model,
                       effort=w.effort, trace_name=w.trace_name, label=w.label)
        if (c := kwargs.get("ctx")) is not None:
            cap.update(user_prompt=c.user, learning_run_dir=c.learning_run_dir,
                       repo_root=c.repo_root, request_limit=c.request_limit,
                       timeout=c.wall_clock_timeout, box=c.box, salt=c.salt)
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
    handoffs = [{"surface": "system", "system": "elastic",
                 "path": "defender/skills/elastic/execution.md",
                 "failures": []}]
    rc = pitfalls_curator._invoke_pitfalls_agent(handoffs, repo_root=tmp_path)
    assert rc == 0
    prompt = cap["user_prompt"]
    assert re.search(r"<run-[0-9a-f]+-pitfalls_handoffs>", prompt)
    assert "skills_dir: defender/skills/" in prompt
    assert "run_dir" not in prompt
    assert "catalog_dir" not in prompt
    assert "executed_template_handoffs" not in prompt


def test_invoke_pitfalls_agent_wires_engine_kwargs_and_pending_anchor(tmp_path: Path, monkeypatch):
    """(rewrite of the RunnerOptions/allowlist-string options-wiring — both are gone) The engine
    gets the pitfalls prompt, the 'pitfalls' batch id, and the injected repo_root. F4: the pitfalls
    curator has NO per-run dir, so its learning trace anchors at PENDING_DIR (the stable cross-run
    queue dir), not a synthesized run dir. Model/effort/request_limit default inside
    run_author_stage (pinned in test_lead_author_engine).

    Since #713 the batch id rides the StageWiring rather than being its own engine kwarg,
    so it stays observable on the trace name and label."""
    cap = _capture_engine(monkeypatch)
    pitfalls_curator._invoke_pitfalls_agent([], repo_root=tmp_path)
    assert cap["system_prompt_file"] == pitfalls_curator.LEAD_PITFALLS_PROMPT
    assert cap["trace_name"].startswith("pitfalls.")
    assert cap["label"].endswith(":pitfalls")
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




def test_pitfalls_commit_message_title_and_body():
    """Fixed 'execution.md pitfalls' title; body lists each changed path as '- {p}'."""
    msg = pitfalls_curator._pitfalls_commit_message(
        ["defender/skills/elastic/execution.md", "defender/skills/cmdb/execution.md"]
    )
    assert "learning(lead-author): execution.md pitfalls" in msg
    assert (
        "git).\n\n"
        "Paths:\n"
        "- defender/skills/elastic/execution.md\n"
        "- defender/skills/cmdb/execution.md\n"
    ) in msg
