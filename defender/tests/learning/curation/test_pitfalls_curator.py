"""Pitfalls curation mode (leads/pitfalls_curator.py): commit-gate verification, the claim's dispositions, and the systemless-batch drop.

The lane works over a batch's git-free draft, never a product worktree. Every gate case drives
the real tick, `run_pitfalls(paths=, trees=, batch=, items=, outcomes=)` over a store claim's pitfall items, with the
spawn faked as an edit of the draft's `agent/skills/`, and reads what landed off the batch branch (`agent/...`).
`paths.repo_root` is the product checkout, holding only the adapters (#1172).

Retired with the file queue (design r8 Items, D1/D9): `test_run_pitfalls_below_threshold_is_noop` (the threshold, and a
queue that stays whole below it, are the store's claim: `LearningStore.claim(thresholds=)`,
`tests/learning/store_1278/test_items_1278.py`), and the queue rotation / consumed ledger the at-threshold and no-edit
ticks asserted: a curated pitfall now stays in its batch (the disposition's `committed_ids`), an uncurable one is skipped.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from defender.learning.leads import pitfalls_curator  # type: ignore[import-not-found]
from defender.learning.leads.lead_extraction import LeadAuthorError  # type: ignore[import-not-found]
from defender.tests.support.shared.contracts._repo import seed_skills_repo
from defender.tests.support.learning.curation import _curator1134 as C


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


def _pitfall_items(n: int, *, system: str = "elastic", start: int = 0) -> list[tuple[str, str, dict]]:
    """``n`` claimed pitfalls (store items `(kind, key, payload)`), each a distinct mistake: #840 collapses rows
    sharing a `stderr_digest` into one record, and the curator counts records."""
    return [
        ("pitfall", f"r:l-{i:03d}:0", {
            "schema_version": 1, "pitfall_id": f"r:l-{i:03d}:0", "source_run": "r",
            "system": system, "query_id": f"{system}.esql", "goal": "g",
            "executed_query": "bad pipe",
            "stderr_digest": f"exit=1; mismatched input at token {i}",
            "error_class": "agent-fixable",
        })
        for i in range(start, start + n)
    ]


class _Claim:
    """What one `run_pitfalls` claim wrote: its `outcomes` (fates) and the dispositions it reported."""

    def __init__(self) -> None:
        self.outcomes: dict = {}
        self.curated: list = []


def _run(lane: C.DraftLane, items, claim: _Claim, invoke) -> int:
    return pitfalls_curator.run_pitfalls(
        paths=lane.paths, trees=C.draft_trees(lane), batch=lane.batch, invoke=invoke,
        items=items, outcomes=claim.outcomes, on_curated=claim.curated.append)


def _tick(lane: C.DraftLane, edit, *, systems: tuple[str, ...] = ("elastic",),
          invoke=None) -> tuple[int, _Claim]:
    """One real pitfalls claim over the draft: two distinct claimed mistakes per system in `systems`, the spawn
    faked as `edit(<the draft's agent/skills>)` (it runs no git)."""
    items = [it for k, system in enumerate(systems)
             for it in _pitfall_items(2, system=system, start=2 * k)]

    def agent(handoffs, **_kw):
        edit(lane.skills_dir)
        return 0

    claim = _Claim()
    return _run(lane, items, claim, invoke or agent), claim


def _refused(lane: C.DraftLane, edit, match: str, *, errors=LeadAuthorError, **kw) -> None:
    """The gate refused the tick naming `match`, and nothing landed on the batch branch."""
    with pytest.raises(errors, match=match):
        _tick(lane, edit, **kw)
    assert lane.landed() == []


def test_verify_pitfalls_state_accepts_execution_md(tmp_path: Path):
    lane = _lane(tmp_path)
    rc, _ = _tick(lane, lambda sk: (sk / "elastic" / "execution.md").write_text(
        "# elastic\n## Common pitfalls\n- use `index=windows`, not `index:windows`\n"))
    assert rc == 0
    assert lane.landed() == ["agent/skills/elastic/execution.md"]


def test_verify_pitfalls_state_rejects_non_execution_md(tmp_path: Path):
    """A SKILL.md edit is in lead-author scope but not pitfalls scope: rejected."""
    _refused(_lane(tmp_path), lambda sk: (sk / "elastic" / "SKILL.md").write_text(
        (sk / "elastic" / "SKILL.md").read_text() + "\nedit\n"), "non-execution.md")


def _stray_errors():
    """An edit outside the lane's `skills/` is refused by the ChangeSet's lane check or by the
    lane's own gate, whichever runs first; both name it outside."""
    from defender.learning.author.version_control import DeliveryRefused

    return (LeadAuthorError, DeliveryRefused)


def test_verify_pitfalls_state_rejects_stray(tmp_path: Path):
    lane = _lane(tmp_path, {"other/stray.md": "committed\n"})
    _refused(lane, lambda sk: (sk.parent / "other" / "stray.md").write_text("x"), "outside",
             errors=_stray_errors())


def test_verify_pitfalls_state_rejects_deletion(tmp_path: Path):
    lane = _lane(tmp_path, {"skills/elastic/execution.md": "# e\n"})
    _refused(lane, lambda sk: (sk / "elastic" / "execution.md").unlink(), "deleted")


def test_verify_pitfalls_stray_wins_over_in_corpus_violation(tmp_path: Path):
    lane = _lane(tmp_path, {"other/stray.md": "committed\n"})

    def edit(sk: Path) -> None:
        (sk.parent / "other" / "stray.md").write_text("stray")
        (sk / "elastic" / "SKILL.md").write_text((sk / "elastic" / "SKILL.md").read_text() + "\nedit\n")

    _refused(lane, edit, "outside", errors=_stray_errors())


def test_verify_pitfalls_state_returns_sorted_changed(tmp_path: Path):
    """A modified and a new execution.md both land, sorted."""
    lane = _lane(tmp_path, {"skills/cmdb/SKILL.md": "---\nname: defender-cmdb\n---\n# cmdb\n",
                            "skills/elastic/execution.md": "# e\n"}, adapters=("cmdb",))

    def edit(sk: Path) -> None:
        (sk / "elastic" / "execution.md").write_text("# e edited\n")
        (sk / "cmdb" / "execution.md").write_text("# c\n")

    rc, _ = _tick(lane, edit, systems=("elastic", "cmdb"))
    assert rc == 0
    assert lane.landed() == [
        "agent/skills/cmdb/execution.md",
        "agent/skills/elastic/execution.md",
    ]


def test_run_pitfalls_commits_the_fold_and_reports_the_claims_pitfalls_as_taken(tmp_path: Path):
    """The curator is handed the system's execution.md, its fold lands on the batch branch, and the claim's
    pitfalls are reported taken (they stay in the batch, none is given a fate). The handoff path's prefix is
    still unsettled, so only its tail and the absence of the product spelling are pinned."""
    lane = _lane(tmp_path)

    def fake_invoke(handoffs, **_kw):
        assert handoffs[0]["system"] == "elastic"
        assert handoffs[0]["path"].endswith("skills/elastic/execution.md")
        assert not handoffs[0]["path"].startswith("defender/")
        assert len(handoffs[0]["failures"]) == 2
        p = lane.skills_dir / "elastic" / "execution.md"
        p.write_text("# elastic\n## Common pitfalls\n- use `index=windows`, not `index:windows`\n")
        return 0

    rc, claim = _tick(lane, None, invoke=fake_invoke)
    assert rc == 0
    assert lane.landed() == ["agent/skills/elastic/execution.md"]
    assert "execution.md pitfalls" in lane.message()
    [taken] = claim.curated
    assert set(taken.committed_ids) == {"r:l-000:0", "r:l-001:0"}
    assert taken.sha == lane.tip()
    assert claim.outcomes == {}


def test_run_pitfalls_no_edit_claim_still_reports_its_pitfalls_taken(tmp_path: Path):
    lane = _lane(tmp_path)
    rc, claim = _tick(lane, lambda sk: None)
    assert rc == 0
    assert lane.commits() == []
    [taken] = claim.curated
    assert set(taken.committed_ids) == {"r:l-000:0", "r:l-001:0"}
    assert taken.sha is None
    assert claim.outcomes == {}


def test_a_queued_system_with_no_skills_dir_never_becomes_a_handoff_path():
    """Only a declared system becomes a handoff (#855); the path's tail is pinned, and it never
    names the product tree."""
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
    tmp_path: Path,
):
    """The commit gate asks whether the directory is a declared system, not merely whether the
    file is an execution.md (#855)."""
    _refused(_lane(tmp_path), lambda sk: C.put(sk / "ghost" / "execution.md",
                                                "# ghost\n## Common pitfalls\n- invented\n"),
             "undeclared system")

    # Positive control on the same gate: the fixture's real system dir takes a NEW execution.md.
    control = _lane(tmp_path / "control")
    rc, _ = _tick(control, lambda sk: (sk / "elastic" / "execution.md").write_text("# e\n"))
    assert rc == 0
    assert control.landed() == ["agent/skills/elastic/execution.md"]


def test_run_pitfalls_all_systemless_skips_the_claim_without_spawn(tmp_path: Path):
    """Pitfalls no declared surface can teach (no system) are skipped, the reason naming why; the curator is never
    spawned and nothing lands."""
    lane = _lane(tmp_path)
    items = [("pitfall", f"r:{i}", {"pitfall_id": f"r:{i}", "system": ""}) for i in range(2)]
    called: list[int] = []
    claim = _Claim()
    rc = _run(lane, items, claim, lambda *a, **k: called.append(1) or 0)
    assert rc == 0
    assert called == []
    assert {k: (o.name, o.reason) for k, o in claim.outcomes.items()} == {
        ("pitfall", "r:0"): ("skipped", "no-system"), ("pitfall", "r:1"): ("skipped", "no-system")}
    assert lane.commits() == []


def _capture_engine(monkeypatch, *, rc: int = 0, raise_exc=None):
    """Patch ``run_author_stage`` on the engine module (``_spawn_author_agent`` looks it up at
    call time), capturing the kwargs the pitfalls spawn forwards; returns ``rc`` or raises."""
    from defender.learning.leads import lead_author_engine

    cap: dict = {}

    def _fake(**kwargs):
        cap.update(kwargs)
        # The spawn forwards a StageWiring/StageContext pair; flatten the fields onto `cap` so a
        # case names one knob.
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
    """A systemic config fault from the engine propagates through the pitfalls spawn, not
    swallowed into an rc."""
    from defender.learning.core.config import FatalConfigError
    _capture_engine(monkeypatch, raise_exc=FatalConfigError("needs FIREWORKS_API_KEY"))
    with pytest.raises(FatalConfigError):
        pitfalls_curator._invoke_pitfalls_agent([], run_dir=tmp_path / "call", repo_root=tmp_path)
