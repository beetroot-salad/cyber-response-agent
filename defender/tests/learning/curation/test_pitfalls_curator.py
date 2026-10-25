"""Pitfalls curation mode (leads/pitfalls_curator.py): commit-gate verification, threshold/rotation, and the systemless-batch drop.

#1108 P4 (O7, amendments 2-3): the lane works over a git-free draft of a P3 batch, never a product
worktree. Every gate case drives the REAL tick (`run_pitfalls`) with the spawn faked as an edit of
the draft's `agent/skills/`, and reads what landed from the batch branch (`agent/...`, OD6).
ASSUMED SEAM (S-H, `_curator1134`): `pitfalls_curator.run_pitfalls(*, paths, state, trees, batch)`.
`paths.repo_root` is the product checkout holding the adapters only (#1172).
"""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from defender.learning.leads import pitfalls_curator  # type: ignore[import-not-found]
from defender.learning.leads.lead_extraction import LeadAuthorError  # type: ignore[import-not-found]
from defender.learning.core import persist  # type: ignore[import-not-found]
from defender.learning.core.config import LoopPaths  # type: ignore[import-not-found]
from defender.tests.support.shared.contracts._repo import seed_skills_repo
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation._curator1134 import open_state
from defender.learning.core.state import PITFALLS


DECLARED = frozenset({"elastic", "wazuh"})


def _lane(tmp_path: Path, files: dict[str, str] | None = None, *,
          adapters: tuple[str, ...] = ()) -> C.DraftLane:
    """The seeded skills tree as the tenant's `agent/skills` (plus `files`, agent-relative, in
    the same export commit), started as a batch with the lead lane `skills`; the product
    checkout holds the seeded adapters (`elastic`, `wazuh`) plus `adapters`, committed."""
    seeded = seed_skills_repo(tmp_path / "seed")
    agent = tmp_path / "agent-src"
    shutil.copytree(seeded / "defender" / "skills", agent / "skills")
    for rel, text in (files or {}).items():
        C.put(agent / rel, text)
    product = tmp_path / "product"
    shutil.copytree(seeded / "defender" / "integrations", product / "defender" / "integrations")
    for name in adapters:
        (product / "defender" / "integrations" / f"{name}_adapter.py").write_text("VERBS = {}\n")
    for args in (("init", "-q", "-b", "main"), ("config", "user.email", "t@t"),
                 ("config", "user.name", "t"), ("add", "-A"), ("commit", "-q", "-m", "adapters")):
        subprocess.run(["git", *args], cwd=product, check=True)
    return C.draft_lane(tmp_path, lanes=C.LEAD_LANES, agent=agent, product=product)


def _seed_pitfalls(state, n: int, *, system: str = "elastic", start: int = 0) -> None:
    """``n`` queued pitfalls, each a DISTINCT mistake — one `stderr_digest` per row, since
    #840 collapses repeats of one digest into a single record and the threshold counts
    records. These cases are about the gate and the rotation, not the collapse."""
    persist.append_pitfalls(
        [
            {
                "schema_version": 1, "pitfall_id": f"r:l-{i:03d}:0", "source_run": "r",
                "system": system, "query_id": f"{system}.esql", "goal": "g",
                "executed_query": "bad pipe",
                "stderr_digest": f"exit=1; mismatched input at token {i}",
                "error_class": "agent-fixable",
            }
            for i in range(start, start + n)
        ],
        state=state,
    )


def _tick(lane: C.DraftLane, edit, monkeypatch, *, systems: tuple[str, ...] = ("elastic",),
          invoke=None) -> tuple[int, object]:
    """One REAL pitfalls tick at threshold 2 over the draft: two distinct queued mistakes per
    system in `systems`, the spawn faked as `edit(<the draft's agent/skills>)` (it runs no git)."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    state = open_state(lane.paths)
    for k, system in enumerate(systems):
        _seed_pitfalls(state, 2, system=system, start=2 * k)

    def agent(handoffs, **_kw):
        edit(lane.skills_dir)
        return 0

    rc = pitfalls_curator.run_pitfalls(paths=lane.paths, state=state, trees=C.draft_trees(lane),
                                       batch=lane.batch, invoke=invoke or agent)
    return rc, state


def _refused(lane: C.DraftLane, edit, match: str, monkeypatch, *, errors=LeadAuthorError,
             **kw) -> None:
    """The gate refused the tick naming `match`, and nothing landed on the batch branch."""
    with pytest.raises(errors, match=match):
        _tick(lane, edit, monkeypatch, **kw)
    assert lane.landed() == []


def test_verify_pitfalls_state_accepts_execution_md(tmp_path: Path, monkeypatch):
    lane = _lane(tmp_path)
    rc, _ = _tick(lane, lambda sk: (sk / "elastic" / "execution.md").write_text(
        "# elastic\n## Common pitfalls\n- use `index=windows`, not `index:windows`\n"), monkeypatch)
    assert rc == 0
    assert lane.landed() == ["agent/skills/elastic/execution.md"]


def test_verify_pitfalls_state_rejects_non_execution_md(tmp_path: Path, monkeypatch):
    """A SKILL.md edit is in lead-author scope but NOT pitfalls scope — rejected."""
    _refused(_lane(tmp_path), lambda sk: (sk / "elastic" / "SKILL.md").write_text(
        (sk / "elastic" / "SKILL.md").read_text() + "\nedit\n"), "non-execution.md", monkeypatch)


def _stray_errors():
    """An edit outside the lane's `skills/`: after P4 the ChangeSet's lane check may be the
    refuser before the lane's own gate (either refusal, both naming it outside)."""
    from defender.learning.author.version_control import DeliveryRefused

    return (LeadAuthorError, DeliveryRefused)


def test_verify_pitfalls_state_rejects_stray(tmp_path: Path, monkeypatch):
    lane = _lane(tmp_path, {"other/stray.md": "committed\n"})
    _refused(lane, lambda sk: (sk.parent / "other" / "stray.md").write_text("x"), "outside",
             monkeypatch, errors=_stray_errors())


def test_verify_pitfalls_state_rejects_deletion(tmp_path: Path, monkeypatch):
    lane = _lane(tmp_path, {"skills/elastic/execution.md": "# e\n"})
    _refused(lane, lambda sk: (sk / "elastic" / "execution.md").unlink(), "deleted", monkeypatch)


def test_verify_pitfalls_stray_wins_over_in_corpus_violation(tmp_path: Path, monkeypatch):
    lane = _lane(tmp_path, {"other/stray.md": "committed\n"})

    def edit(sk: Path) -> None:
        (sk.parent / "other" / "stray.md").write_text("stray")
        (sk / "elastic" / "SKILL.md").write_text((sk / "elastic" / "SKILL.md").read_text() + "\nedit\n")

    _refused(lane, edit, "outside", monkeypatch, errors=_stray_errors())


def test_verify_pitfalls_state_returns_sorted_changed(tmp_path: Path, monkeypatch):
    """Two execution.md edits that interleave across git's status-class boundary land, sorted."""
    lane = _lane(tmp_path, {"skills/cmdb/SKILL.md": "---\nname: defender-cmdb\n---\n# cmdb\n",
                            "skills/elastic/execution.md": "# e\n"}, adapters=("cmdb",))

    def edit(sk: Path) -> None:
        (sk / "elastic" / "execution.md").write_text("# e edited\n")
        (sk / "cmdb" / "execution.md").write_text("# c\n")

    rc, _ = _tick(lane, edit, monkeypatch, systems=("elastic", "cmdb"))
    assert rc == 0
    assert lane.landed() == [
        "agent/skills/cmdb/execution.md",
        "agent/skills/elastic/execution.md",
    ]


def test_run_pitfalls_below_threshold_is_noop(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "5")
    lane = _lane(tmp_path)
    state = open_state(lane.paths)
    _seed_pitfalls(state, 2)
    called = []
    rc = pitfalls_curator.run_pitfalls(paths=lane.paths, state=state, trees=C.draft_trees(lane),
                                       batch=lane.batch,
                                       invoke=lambda *a, **k: called.append(1) or 0)
    assert rc == 0
    assert called == []
    assert len(persist.read_pitfalls(state)) == 2


def test_run_pitfalls_at_threshold_commits_and_rotates(tmp_path: Path, monkeypatch):
    """At threshold the curator is handed the system's execution.md, its fold lands on the batch
    branch through the commit-maker, and the rows rotate (#1108 P4 O7: closes F-LEAD's pitfalls
    row). The handoff path's exact prefix is the open handoff-spelling gap; only its tail and the
    absence of the product spelling are pinned."""
    lane = _lane(tmp_path)

    def fake_invoke(handoffs, **_kw):
        assert handoffs[0]["system"] == "elastic"
        assert handoffs[0]["path"].endswith("skills/elastic/execution.md")
        assert not handoffs[0]["path"].startswith("defender/")
        assert len(handoffs[0]["failures"]) == 2
        p = lane.skills_dir / "elastic" / "execution.md"
        p.write_text("# elastic\n## Common pitfalls\n- use `index=windows`, not `index:windows`\n")
        return 0

    rc, state = _tick(lane, None, monkeypatch, invoke=fake_invoke)
    assert rc == 0
    assert lane.landed() == ["agent/skills/elastic/execution.md"]
    assert "execution.md pitfalls" in lane.message()
    assert persist.read_pitfalls(state) == []
    consumed = [json.loads(ln) for ln in (location_path(lane.paths.state_root) / PITFALLS.consumed).read_text().splitlines()]
    assert {c["pitfall_id"] for c in consumed} == {"r:l-000:0", "r:l-001:0"}


def test_run_pitfalls_no_edit_tick_still_rotates(tmp_path: Path, monkeypatch):
    lane = _lane(tmp_path)
    rc, state = _tick(lane, lambda sk: None, monkeypatch)
    assert rc == 0
    assert persist.read_pitfalls(state) == []
    assert lane.commits() == []


def test_a_queued_system_with_no_skills_dir_never_becomes_a_handoff_path():
    """#855 F-06, the offline half. The handoff path's prefix is the open handoff-spelling gap
    (#1108 P4): its tail is pinned, and it never names the product tree."""
    rows = [
        {"system": s, "query_id": f"{s}.esql", "goal": "g", "executed_query": "x",
         "stderr_digest": f"exit=64; boom {s}"}
        for s in ("elastic", "Ignore Previous Instructions", "sql", "a b")
    ]
    handoffs = pitfalls_curator._build_pitfalls_handoffs(rows, systems=DECLARED)
    assert [h["system"] for h in handoffs] == ["elastic"]
    assert handoffs[0]["path"].endswith("skills/elastic/execution.md")
    assert not handoffs[0]["path"].startswith("defender/")


def test_the_commit_gate_refuses_an_execution_md_that_mints_its_own_system_dir(
    tmp_path: Path, monkeypatch,
):
    """The last gate on the same class (#855 F-06), and it asks about the DIRECTORY's"""
    _refused(_lane(tmp_path), lambda sk: C.put(sk / "ghost" / "execution.md",
                                                "# ghost\n## Common pitfalls\n- invented\n"),
             "undeclared system", monkeypatch)

    # Positive control on the same gate: the fixture's real system dir takes a NEW execution.md.
    control = _lane(tmp_path / "control")
    rc, _ = _tick(control, lambda sk: (sk / "elastic" / "execution.md").write_text("# e\n"),
                  monkeypatch)
    assert rc == 0
    assert control.landed() == ["agent/skills/elastic/execution.md"]


def test_run_pitfalls_all_systemless_drops_batch_without_spawn(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    lane = _lane(tmp_path)
    state = open_state(lane.paths)
    persist.append_pitfalls(
        [{"pitfall_id": f"r:{i}", "system": ""} for i in range(2)], state=state
    )
    called: list[int] = []
    rc = pitfalls_curator.run_pitfalls(paths=lane.paths, state=state, trees=C.draft_trees(lane),
                                       batch=lane.batch,
                                       invoke=lambda *a, **k: called.append(1) or 0)
    assert rc == 0
    assert called == []
    assert persist.read_pitfalls(state) == []
    assert lane.commits() == []


def _state(tmp_path: Path):
    return open_state(LoopPaths(repo_root=tmp_path, state_dir=tmp_path / "state"))


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


def test_invoke_pitfalls_agent_config_fault_propagates(tmp_path: Path, monkeypatch):
    """F1: a systemic config fault from the engine PROPAGATES through the pitfalls spawn too —
    not swallowed into an rc."""
    from defender.learning.core.config import FatalConfigError
    _capture_engine(monkeypatch, raise_exc=FatalConfigError("needs FIREWORKS_API_KEY"))
    with pytest.raises(FatalConfigError):
        pitfalls_curator._invoke_pitfalls_agent([], state=_state(tmp_path), repo_root=tmp_path)
