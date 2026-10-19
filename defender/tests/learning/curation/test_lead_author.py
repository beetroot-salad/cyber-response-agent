"""Lead-author driver: lead extraction, handoff shape, lock/sentinel paths, and the post-flight skills scope gate."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from defender.tests.support.learning.curation._claim1175 import claim_git
from defender.learning.author import shared as author_shared
from defender.learning.leads import lead_author  # type: ignore[import-not-found]
from defender.learning.core.config import LoopPaths  # type: ignore[import-not-found]
from defender.tests.support.shared.contracts._repo import query_template, seed_skills_repo
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender.learning.core.state import LEAD_QUEUE_LOCK, PITFALLS, TRY_ONCE
from defender.tests.support.learning.curation._lead_author_1134 import lane_tree_for, lead_deps, repo_skills, skills_view
from defender.tests.support.learning.core._state1135 import curation_run_dir, run_of


def _ensure_declarable(repo_root: Path) -> None:
    """`build_lead_author_deps` resolves `declared_systems` at its own boundary (#869) —
    every caller needs a real, committed adapter for that resolution to answer from rather
    than raise. Idempotent, so a caller that already seeded (or committed) its own tree is
    left alone; `elastic` is the name every other fixture in this file already assumes."""
    adapters = repo_root / "defender" / "scripts" / "adapters"
    if not adapters.is_dir():
        adapters.mkdir(parents=True)
        (adapters / "elastic_adapter.py").write_text("VERBS = {}\n")
    skills = repo_root / "defender" / "skills"
    skills.mkdir(parents=True, exist_ok=True)
    if not any(skills.rglob("*")):
        (skills / ".gitkeep").write_text("")
    if not (repo_root / ".git").is_dir():
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo_root, check=True)
        subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo_root, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=repo_root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo_root, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "seed", "--allow-empty"], cwd=repo_root, check=False,
    )


def _deps(tmp_path: Path, **overrides):
    """Production lead-author deps rooted at a tmp tree, with leaf collaborators
    overridden by keyword — replaces monkeypatching lead_author's own functions."""
    _ensure_declarable(tmp_path)
    return replace(lead_deps(LoopPaths(repo_root=tmp_path)), **overrides)


def _executed_lead(**kw):
    """A minimal ``ExecutedLead`` for flow + collection tests. Defaults to an
    ``ok`` lead (``error_class=None``) so ``collect_general_failures`` is a no-op
    unless a test opts into a failure via ``error_class=`` / ``query_id=``."""
    base = dict(
        lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
        query_id="elastic.esql", system="elastic", verb="esql", params={}, raw_command="cli",
        goal_text="", what_to_summarize=(), raw_ref=None,
        payload_status="ok", payload_digest="", error_class=None,
    )
    base.update(kw)
    return lead_author.ExecutedLead(**base)


def _write_lead_meta(run_dir: Path, lead_id: str, goal: str, wts=()) -> None:
    raw = run_dir / "gather_raw"
    raw.mkdir(exist_ok=True)
    (raw / f"{lead_id}.lead.json").write_text(
        json.dumps({"goal": goal, "what_to_summarize": list(wts)})
    )


def _write_query(  # noqa: PLR0913 — a queries-row builder mirrors the table's columns
    run_dir: Path,
    lead_id: str,
    seq: int,
    query_id: str,
    params: dict | None = None,
    *,
    verb: str | None = None,
    payload: str | None = "{}",
    payload_status: str = "ok",
    payload_digest: str = "ok digest",
) -> None:
    """Append one queries-table row + (optionally) its by-ref payload.

    ``verb`` is the honest registry verb the row freezes (#620); it defaults to the query_id
    suffix (the untagged shape) — pass it explicitly to exercise an engine verb or a coined id
    whose suffix is not the verb."""
    raw = run_dir / "gather_raw"
    raw.mkdir(exist_ok=True)
    rel = None
    if payload is not None:
        ld = raw / lead_id
        ld.mkdir(exist_ok=True)
        (ld / f"{seq}.json").write_text(payload)
        rel = f"gather_raw/{lead_id}/{seq}.json"
    row = {
        "lead_id": lead_id,
        "seq": seq,
        "system": query_id.split(".", 1)[0] if "." in query_id else query_id,
        "verb": verb if verb is not None else query_id.split(".", 1)[-1],
        "query_id": query_id,
        "params": params or {},
        "raw_command": "cli",
        "payload_path": rel,
        "exit_code": 0 if payload_status != "error" else 1,
        "payload_status": payload_status,
        "payload_digest": payload_digest,
    }
    with (run_dir / "executed_queries.jsonl").open("a") as fh:
        fh.write(json.dumps(row) + "\n")


@pytest.fixture
def run_dir() -> Path:
    # A natural run where run setup leaves one (`<data root>/<T>/runs/<id>`): the lane takes it
    # as the `Run` its open hands it (`run_of`, #1105 PR 2).
    rd = curation_run_dir("test-run-001")
    (rd / "gather_raw").mkdir()
    return rd


@pytest.fixture
def catalog(tmp_path: Path) -> Path:
    """Self-contained query catalog so build_handoff resolves ids without
    depending on the live, environment-specific on-disk catalog (v2 ships an
    elastic/host-state/cmdb catalog; main ships wazuh). Returns the catalog dir;
    tests pass it as ``build_handoff(..., repo_root=catalog.parent,
    skills=skills_view(catalog.parents[1]), where=catalog.parents[1])``
    (the read root + the relative-path anchor), so no module-global patch is needed."""
    cat = tmp_path / "skills" / "gather" / "queries"
    (cat / "elastic").mkdir(parents=True)
    (cat / "host-state").mkdir(parents=True)
    (cat / "elastic" / "auth-events.md").write_text(
        "---\nid: elastic.auth-events\nstatus: established\n---\n\n"
        "## Goal\nAuthentication events for a host over a window.\n\n"
        "## Query\n\n```\nelastic_adapter.py query --window ${window} ${host_clause}\n```\n"
    )
    (cat / "host-state" / "process-list.md").write_text(
        "---\nid: host-state.process-list\nstatus: established\n---\n\n"
        "## Goal\nRunning processes matching a pattern.\n\n"
        "## Query\n\n```\nhost_state_adapter.py process-list ${pattern}\n```\n"
    )
    return cat


def test_extract_single_query_per_entry(run_dir: Path):
    _write_lead_meta(run_dir, "l-001", "list auth events", ["src_ip", "user"])
    _write_query(run_dir, "l-001", 0, "wazuh.auth-events", {"host": "h1", "window": "1h"})
    _, leads = lead_author.extract(run_dir)
    assert len(leads) == 1
    lead = leads[0]
    assert lead.lead_id == "l-001"
    assert lead.query_index == 0
    assert lead.is_multi_query is False
    assert lead.query_id == "wazuh.auth-events"
    assert lead.params == {"host": "h1", "window": "1h"}
    assert lead.goal_text == "list auth events"
    assert lead.what_to_summarize == ("src_ip", "user")
    assert lead.raw_ref == run_dir / "gather_raw" / "l-001" / "0.json"
    assert lead.payload_status == "ok"


def test_extract_multi_query_fans_out(run_dir: Path):
    _write_lead_meta(run_dir, "l-001", "fan out")
    _write_query(run_dir, "l-001", 0, "wazuh.auth-events")
    _write_query(run_dir, "l-001", 1, "wazuh.sudo-commands")
    _, leads = lead_author.extract(run_dir)
    assert len(leads) == 2
    assert leads[0].query_index == 0
    assert leads[0].is_multi_query is True
    assert leads[0].raw_ref.name == "0.json"
    assert leads[1].query_index == 1
    assert leads[1].query_id == "wazuh.sudo-commands"
    assert leads[1].raw_ref.name == "1.json"


def test_extract_multi_query_skips_missing_payload(run_dir: Path):
    _write_lead_meta(run_dir, "l-001", "partial fan-out")
    _write_query(run_dir, "l-001", 0, "wazuh.auth-events")
    _write_query(run_dir, "l-001", 1, "wazuh.sudo-commands", payload=None)
    _, leads = lead_author.extract(run_dir)
    assert len(leads) == 1
    assert leads[0].query_id == "wazuh.auth-events"


def test_extract_missing_payload_status_raises(run_dir: Path):
    """An empty payload_status (no row status) is a loud failure."""
    _write_lead_meta(run_dir, "l-001", "x")
    _write_query(run_dir, "l-001", 0, "wazuh.auth-events", payload_status="")
    with pytest.raises(lead_author.LeadAuthorError, match="payload_status"):
        lead_author.extract(run_dir)


def test_extract_invalid_payload_status_raises(run_dir: Path):
    _write_lead_meta(run_dir, "l-001", "x")
    _write_query(run_dir, "l-001", 0, "wazuh.auth-events", payload_status="weird")
    with pytest.raises(lead_author.LeadAuthorError, match="payload_status"):
        lead_author.extract(run_dir)


def test_build_handoff_groups_by_template(run_dir: Path, catalog: Path):
    """Same template invoked across 3 leads → one handoff with 3 invocations."""
    for i in range(3):
        lid = f"l-00{i + 1}"
        _write_lead_meta(run_dir, lid, f"call {i}")
        _write_query(run_dir, lid, 0, "elastic.auth-events", {"host": f"h{i}"},
                     payload_digest=f"call-{i}")
    _, leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(
        run_dir, leads, repo_root=catalog.parent, skills=skills_view(catalog.parents[1]),
        where=catalog.parents[1]
    )
    assert len(handoffs) == 1
    h = handoffs[0]
    assert h["query_id"] == "elastic.auth-events"
    assert h["status"] == "established"
    assert h["executed_template_path"].endswith("elastic/auth-events.md")
    assert len(h["invocations"]) == 3
    assert [inv["payload_digest"] for inv in h["invocations"]] == [
        "call-0", "call-1", "call-2",
    ]
    json.dumps(h)


def test_build_handoff_drops_unresolved_query_id(run_dir: Path, catalog: Path):
    """Unresolved query_id ⇒ skip with a corpus-health warning, don't crash."""
    _write_lead_meta(run_dir, "l-001", "novel")
    _write_query(run_dir, "l-001", 0, "elastic.does-not-exist")
    _write_lead_meta(run_dir, "l-002", "real one")
    _write_query(run_dir, "l-002", 0, "elastic.auth-events")
    _, leads = lead_author.extract(run_dir)
    assert len(leads) == 2
    handoffs = lead_author.build_handoff(
        run_dir, leads, repo_root=catalog.parent, skills=skills_view(catalog.parents[1]),
        where=catalog.parents[1]
    )
    assert len(handoffs) == 1
    assert handoffs[0]["query_id"] == "elastic.auth-events"


def test_build_handoff_drops_ad_hoc_empty_query_id(run_dir: Path):
    _write_lead_meta(run_dir, "l-001", "ad-hoc")
    _write_query(run_dir, "l-001", 0, "")
    _, leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(run_dir, leads, **repo_skills())
    assert handoffs == []


def test_build_handoff_one_handoff_per_template_cross_system(run_dir: Path, catalog: Path):
    """A multi-query, cross-system lead yields one handoff per executed template."""
    _write_lead_meta(run_dir, "l-001", "cross-system")
    _write_query(run_dir, "l-001", 0, "elastic.auth-events")
    _write_query(run_dir, "l-001", 1, "host-state.process-list", {"pattern": "x"})
    _, leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(
        run_dir, leads, repo_root=catalog.parent, skills=skills_view(catalog.parents[1]),
        where=catalog.parents[1]
    )
    assert len(handoffs) == 2
    by_id = {h["query_id"]: h for h in handoffs}
    assert set(by_id) == {"elastic.auth-events", "host-state.process-list"}
    assert len(by_id["elastic.auth-events"]["invocations"]) == 1


def _claude_should_not_be_called(*args, **kwargs):
    raise AssertionError("claude was spawned despite gating check")


def test_run_held_queue_lock_reports_a_skip_not_a_serve(run_dir: Path, tmp_path: Path):
    deps = _deps(tmp_path, invoke_agent=_claude_should_not_be_called)
    with deps.state.lock(LEAD_QUEUE_LOCK, wait=TRY_ONCE) as held:
        assert held, "the test could not take the queue lock it means to hold"
        rc = lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps)
    assert rc == lead_author.QUEUE_LOCK_SKIP_RC
    assert rc != 0


def test_run_done_sentinel_short_circuits(run_dir: Path, tmp_path: Path):
    state = run_dir / "lead_author"
    state.mkdir()
    (state / "done").write_text("ok")
    deps = _deps(
        tmp_path,
        invoke_agent=_claude_should_not_be_called,
    )
    assert lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps) == 0


def test_discover_system_drafts_finds_files_excluding_readme(tmp_path):
    """README.md and _TEMPLATE.md are surface declarations, not drafts."""
    skills = tmp_path / "defender" / "skills"
    (skills / "elastic" / "_draft").mkdir(parents=True)
    (skills / "elastic" / "_draft" / "README.md").write_text("surface declaration\n")
    (skills / "elastic" / "_draft" / "real-draft.md").write_text("---\nstatus: draft\n---\n")
    (skills / "elastic" / "SKILL.md").write_text("# elastic\n")
    (skills / "wazuh").mkdir()
    (skills / "wazuh" / "SKILL.md").write_text("# wazuh\n")
    (skills / "gather" / "queries" / "elastic" / "_draft").mkdir(parents=True)
    (skills / "gather" / "queries" / "elastic" / "_draft" / "ignore.md").write_text("ignore\n")
    (skills / "cmdb" / "_draft").mkdir(parents=True)
    (skills / "cmdb" / "_draft" / "_TEMPLATE.md").write_text("template\n")

    found = lead_author.discover_system_drafts(
        skills=skills_view(skills), where=skills, systems=frozenset({"elastic", "wazuh", "cmdb"}))
    rel = [str(p.relative_to(tmp_path)) for p in found]
    assert rel == ["defender/skills/elastic/_draft/real-draft.md"]


def test_build_system_draft_handoffs_emits_triple(tmp_path):
    skills = tmp_path / "defender" / "skills"
    (skills / "elastic" / "_draft").mkdir(parents=True)
    draft = skills / "elastic" / "_draft" / "falco-na.md"
    draft.write_text("---\nstatus: draft\n---\n")
    handoffs = lead_author.build_system_draft_handoffs([draft], repo_root=tmp_path)
    assert handoffs == [{
        "draft_path": "defender/skills/elastic/_draft/falco-na.md",
        "system": "elastic",
        "skill_path": "defender/skills/elastic/SKILL.md",
    }]


def _run_git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd,
                          capture_output=True, text=True, check=True)


_CATALOG = "defender/skills/gather/queries"

#: `tests/_repo.seed_skills_repo`'s adapter-declared systems (#869) — threaded explicitly,
#: since every consumer answers from the value it is handed rather than re-deriving the tree.
DECLARED = frozenset({"elastic", "wazuh"})


@pytest.fixture
def tmp_git_repo(tmp_path: Path) -> Path:
    """A clean git repo with a seeded skills tree (committed) — stands in for a fresh
    ``lead-author/<id>`` worktree. The agent runs no git, so tests then make *working-tree*
    edits and call ``_verify_skills_state`` / drive ``run`` over them, asserting the loop's
    gate + commit behavior."""
    return seed_skills_repo(tmp_path / "repo")


def test_verify_skills_state_accepts_in_scope_edits(tmp_git_repo: Path):
    """Fold an established template, promote a draft (write established + rm draft), and
    lift a system skill (edit SKILL.md + rm draft) — all in-scope; returns changed paths."""
    repo = tmp_git_repo
    (repo / _CATALOG / "wazuh" / "auth-events.md").write_text(
        query_template("wazuh.auth-events", "established") + "\n# folded\n"
    )
    (repo / _CATALOG / "wazuh" / "newthing.md").write_text(
        query_template("wazuh.newthing", "established")
    )
    (repo / _CATALOG / "wazuh" / "_draft" / "newthing.md").unlink()
    skill = repo / "defender" / "skills" / "elastic" / "SKILL.md"
    skill.write_text(skill.read_text() + "\n## Falco quirk\nworkaround\n")
    (repo / "defender" / "skills" / "elastic" / "_draft" / "falco-na.md").unlink()

    changed = lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED,
                                               tree_for=lane_tree_for(repo), git=claim_git(repo))
    assert "defender/skills/gather/queries/wazuh/auth-events.md" in changed
    assert "defender/skills/gather/queries/wazuh/newthing.md" in changed
    assert "defender/skills/elastic/SKILL.md" in changed


def _commit_outside(repo: Path) -> Path:
    """A committed file outside `skills/`, for a stray edit. An edit, not a new file: the lanes
    list untracked files only under `skills/` (#1175 N1 — the agent cannot write elsewhere)."""
    stray = repo / "defender" / "other" / "stray.md"
    stray.parent.mkdir(parents=True, exist_ok=True)
    stray.write_text("committed\n")
    _run_git(repo, "add", "--", str(stray))
    _run_git(repo, "commit", "-q", "-m", "outside skills")
    return stray


def test_verify_skills_state_rejects_stray_outside_skills(tmp_git_repo: Path):
    _commit_outside(tmp_git_repo).write_text("stray")
    with pytest.raises(lead_author.LeadAuthorError, match="outside"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[], systems=DECLARED,
                                         tree_for=lane_tree_for(tmp_git_repo), git=claim_git(tmp_git_repo))


def _append(path: Path, text: str) -> None:
    path.write_text(path.read_text() + text)


@pytest.mark.parametrize(("case", "mutate", "match"), [
    # a non-*.md file under defender/skills/ is a stray — the corpus is *.md
    ("non-md-under-skills",
     lambda r: (r / "defender" / "skills" / "junk.json").write_text("{}"), "outside"),

    # deleting an ESTABLISHED template, and deleting a system's SKILL.md, are both the
    # delete-prohibition: a promote writes, it never removes what another run relies on
    ("established-template-deletion",
     lambda r: (r / _CATALOG / "wazuh" / "auth-events.md").unlink(), "delete-prohibition"),
    ("skill-md-deletion",
     lambda r: (r / "defender" / "skills" / "elastic" / "SKILL.md").unlink(),
     "delete-prohibition"),

    # the `_draft/README.md` is scaffold the lane may not author over
    ("draft-readme-mutation",
     lambda r: _append(r / "defender" / "skills" / "elastic" / "_draft" / "README.md",
                       "\nstomped\n"),
     "protected surface"),

    ("half-promote",
     lambda r: (r / _CATALOG / "wazuh" / "newthing.md").write_text(
         query_template("wazuh.newthing", "established")), "half-promote"),

    ("skill-md-naming-another-system",
     lambda r: (r / "defender" / "skills" / "elastic" / "SKILL.md").write_text(
         "---\nname: defender-cmdb\n---\n# elastic\n"), "defender-elastic"),
], ids=lambda v: v if isinstance(v, str) and len(v) < 50 and " " not in v else "")
def test_verify_skills_state_rejects_a_tree_the_write_lane_could_produce(
    tmp_git_repo: Path, case, mutate, match
):
    mutate(tmp_git_repo)
    with pytest.raises(lead_author.LeadAuthorError, match=match):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[], systems=DECLARED,
                                         tree_for=lane_tree_for(tmp_git_repo), git=claim_git(tmp_git_repo))


def test_verify_skills_state_rejects_out_of_scope_skills_md(tmp_git_repo: Path):
    (tmp_git_repo / "defender" / "skills" / "elastic" / "notes.md").write_text("x")
    with pytest.raises(lead_author.LeadAuthorError, match="out-of-scope"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[], systems=DECLARED,
                                         tree_for=lane_tree_for(tmp_git_repo), git=claim_git(tmp_git_repo))


def test_verify_skills_state_rejects_execution_md(tmp_git_repo: Path):
    """`execution.md` is the one per-system file the lead-author lane can never get
    committed (#869 C32/F1) — under NF1 the commit gate IS the marker's integrity."""
    (tmp_git_repo / "defender" / "skills" / "elastic" / "execution.md").write_text("x")
    with pytest.raises(lead_author.LeadAuthorError, match="execution.md"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[], systems=DECLARED,
                                         tree_for=lane_tree_for(tmp_git_repo), git=claim_git(tmp_git_repo))


def _stage_covered_draft(repo: Path, query_id: str) -> Path:
    """Commit a `wazuh` draft that accounts for `query_id`, as the mint would write it.

    Committed, not merely written, because the invariants under test read the draft's PRE-IMAGE
    out of `git show HEAD:…` — a draft that only ever existed in the working tree carries no
    identities to orphan when the agent deletes it.
    """
    draft = repo / _CATALOG / "wazuh" / "_draft" / f"{lead_author._draft_basename(query_id)}.md"
    draft.write_text(query_template(f"wazuh.{lead_author._draft_basename(query_id)}",
                                    "draft", covers=[query_id]))
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "mint"], cwd=repo, check=True)
    return draft


def test_a_discard_into_widen_that_carries_covers_is_accepted(tmp_git_repo: Path):
    repo = tmp_git_repo
    draft = _stage_covered_draft(repo, "wazuh.hunt-failed-logins")
    (repo / _CATALOG / "wazuh" / "auth-events.md").write_text(
        query_template("wazuh.auth-events", "established",
                       covers=["wazuh.hunt-failed-logins"]) + "\n# widened\n"
    )
    draft.unlink()

    changed = lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED,
                                               tree_for=lane_tree_for(repo), git=claim_git(repo))
    assert "defender/skills/gather/queries/wazuh/auth-events.md" in changed


def test_a_bare_discard_of_a_covered_draft_is_refused(tmp_git_repo: Path):
    repo = tmp_git_repo
    draft = _stage_covered_draft(repo, "wazuh.hunt-failed-logins")
    draft.unlink()

    with pytest.raises(lead_author.LeadAuthorError, match="wazuh.hunt-failed-logins"):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED,
                                         tree_for=lane_tree_for(repo), git=claim_git(repo))


def _mint_uncommitted_draft(repo: Path, query_id: str) -> Path:
    """A `wazuh` draft written but NOT committed — what `synthesize_drafts` leaves behind, and
    what the same tick then hands to the author.

    `covers:` carries BOTH identities the real mint writes: the draft's own derived id (which
    `template_search` publishes and gather may bind) and the coined `query_id`. A fixture that
    wrote only one would test a file the loop never produces."""
    draft_id = f"wazuh.{lead_author._draft_basename(query_id)}"
    draft = repo / _CATALOG / "wazuh" / "_draft" / f"{lead_author._draft_basename(query_id)}.md"
    draft.write_text(query_template(draft_id, "draft", covers=[draft_id, query_id]))
    return draft


def test_a_promote_of_a_draft_minted_this_tick_is_accepted(tmp_git_repo: Path):
    """The positive control for the rule above — the identity lands, so the delete costs
    nothing and the batch commits."""
    repo = tmp_git_repo
    draft = _mint_uncommitted_draft(repo, "wazuh.hunt-failed-logins")
    minted = lead_author._minted_identities(
        skills_view(repo / "defender" / "skills"), [draft], where=repo / "defender" / "skills")
    (repo / _CATALOG / "wazuh" / "auth-failure-rate.md").write_text(
        query_template("wazuh.auth-failure-rate", "established",
                       covers=[draft.stem.join(("wazuh.", "")), "wazuh.hunt-failed-logins"])
    )
    draft.unlink()

    changed = lead_author._verify_skills_state(
        repo, baseline_stray=[], systems=DECLARED, minted=minted, tree_for=lane_tree_for(repo), git=claim_git(repo)
    )
    assert "defender/skills/gather/queries/wazuh/auth-failure-rate.md" in changed


def test_a_draft_minted_this_tick_and_left_alone_is_not_a_departure(tmp_git_repo: Path):
    """SKIP is a legal disposition, and it is the one the prompt names for a draft that fits
    nowhere — the rule must fire on the `rm`, never on the file still being there."""
    repo = tmp_git_repo
    draft = _mint_uncommitted_draft(repo, "wazuh.hunt-failed-logins")
    minted = lead_author._minted_identities(
        skills_view(repo / "defender" / "skills"), [draft], where=repo / "defender" / "skills")

    changed = lead_author._verify_skills_state(
        repo, baseline_stray=[], systems=DECLARED, minted=minted, tree_for=lane_tree_for(repo), git=claim_git(repo)
    )
    assert changed == [draft.relative_to(repo).as_posix()]


def test_a_promote_that_leaves_the_draft_behind_is_refused(tmp_git_repo: Path):
    repo = tmp_git_repo
    _stage_covered_draft(repo, "wazuh.hunt-failed-logins")
    (repo / _CATALOG / "wazuh" / "auth-failure-rate.md").write_text(
        query_template("wazuh.auth-failure-rate", "established",
                       covers=["wazuh.hunt-failed-logins"])
    )
    # …and no `rm` of the draft.
    with pytest.raises(lead_author.LeadAuthorError, match="half-promote"):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED,
                                         tree_for=lane_tree_for(repo), git=claim_git(repo))


def test_a_discard_is_accepted_when_an_untouched_template_already_covers_it(
    tmp_git_repo: Path,
):
    repo = tmp_git_repo
    draft = _stage_covered_draft(repo, "wazuh.hunt-failed-logins")
    established = repo / _CATALOG / "wazuh" / "auth-events.md"
    established.write_text(
        query_template("wazuh.auth-events", "established", covers=["wazuh.hunt-failed-logins"])
    )
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "widened last tick"], cwd=repo, check=True)

    draft.unlink()
    changed = lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED,
                                               tree_for=lane_tree_for(repo), git=claim_git(repo))
    assert changed == ["defender/skills/gather/queries/wazuh/_draft/"
                       f"{lead_author._draft_basename('wazuh.hunt-failed-logins')}.md"]


def test_repairing_an_id_that_disagrees_with_its_directory_is_not_a_clobber(
    tmp_git_repo: Path
):
    repo = tmp_git_repo
    broken = repo / _CATALOG / "wazuh" / "auth-events.md"
    broken.write_text(query_template("elastic.auth-events", "established"))
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "a mismatched id"], cwd=repo, check=True)

    broken.write_text(query_template("wazuh.auth-events", "established"))
    changed = lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED,
                                               tree_for=lane_tree_for(repo), git=claim_git(repo))
    assert "defender/skills/gather/queries/wazuh/auth-events.md" in changed


def test_a_draft_folded_into_another_draft_is_attributed(tmp_git_repo: Path):
    repo = tmp_git_repo
    narrow = _mint_uncommitted_draft(repo, "wazuh.narrow-probe")
    wide = _mint_uncommitted_draft(repo, "wazuh.wide-probe")
    minted = lead_author._minted_identities(
        skills_view(repo / "defender" / "skills"), [narrow, wide],
        where=repo / "defender" / "skills")

    # The survivor absorbs the narrow one's identities; the narrow one goes.
    wide.write_text(query_template(
        f"wazuh.{lead_author._draft_basename('wazuh.wide-probe')}", "draft",
        covers=[
            f"wazuh.{lead_author._draft_basename('wazuh.wide-probe')}", "wazuh.wide-probe",
            f"wazuh.{lead_author._draft_basename('wazuh.narrow-probe')}", "wazuh.narrow-probe",
        ],
    ))
    narrow.unlink()

    changed = lead_author._verify_skills_state(
        repo, baseline_stray=[], systems=DECLARED, minted=minted, tree_for=lane_tree_for(repo), git=claim_git(repo)
    )
    assert wide.relative_to(repo).as_posix() in changed


def test_an_established_template_may_not_lose_the_identities_it_covers(tmp_git_repo: Path):
    repo = tmp_git_repo
    established = repo / _CATALOG / "wazuh" / "auth-events.md"
    established.write_text(
        query_template("wazuh.auth-events", "established", covers=["wazuh.old-probe"])
    )
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "covered"], cwd=repo, check=True)

    established.write_text(query_template("wazuh.auth-events", "established"))
    with pytest.raises(lead_author.LeadAuthorError, match="wazuh.old-probe"):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED,
                                         tree_for=lane_tree_for(repo), git=claim_git(repo))


def test_an_established_template_may_not_have_its_id_rewritten(tmp_git_repo: Path):
    repo = tmp_git_repo
    (repo / _CATALOG / "wazuh" / "auth-events.md").write_text(
        query_template("wazuh.something-else", "established")
    )
    with pytest.raises(lead_author.LeadAuthorError, match="rewrote the identity"):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED,
                                         tree_for=lane_tree_for(repo), git=claim_git(repo))


def test_verify_skills_state_rejects_schema_mutation(tmp_git_repo: Path):
    schema = tmp_git_repo / _CATALOG / "SCHEMA.md"
    schema.write_text(schema.read_text() + "\nstomped\n")
    with pytest.raises(lead_author.LeadAuthorError, match="protected surface"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[], systems=DECLARED,
                                         tree_for=lane_tree_for(tmp_git_repo), git=claim_git(tmp_git_repo))


def test_verify_skills_state_rejects_a_promotion_whose_placeholder_is_not_a_param(
    tmp_git_repo: Path,
):
    repo = tmp_git_repo
    (repo / _CATALOG / "wazuh" / "newthing.md").write_text(
        query_template(
            "wazuh.newthing", "established",
            body="```query\nverb: search\nparams:\n  index: ${mystery}\n```",
        )
    )
    (repo / _CATALOG / "wazuh" / "_draft" / "newthing.md").unlink()
    with pytest.raises(lead_author.LeadAuthorError, match="mystery"):
        lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED,
                                         tree_for=lane_tree_for(repo), git=claim_git(repo))


def test_verify_skills_state_accepts_a_malformed_draft(tmp_git_repo: Path):
    repo = tmp_git_repo
    (repo / _CATALOG / "wazuh" / "_draft" / "rough.md").write_text(
        query_template(
            "wazuh.rough", "draft",
            body="```query\nverb: search\nparams:\n  index: ${mystery}\n```",
        )
    )
    changed = lead_author._verify_skills_state(repo, baseline_stray=[], systems=DECLARED,
                                               tree_for=lane_tree_for(repo), git=claim_git(repo))
    assert "defender/skills/gather/queries/wazuh/_draft/rough.md" in changed


def test_is_catalog_template_excludes_what_is_not_a_template(tmp_git_repo: Path):
    assert lead_author._is_catalog_template("defender/skills/gather/queries/wazuh/auth.md")
    assert not lead_author._is_catalog_template("defender/skills/gather/queries/wazuh/README.md")
    assert not lead_author._is_catalog_template("defender/skills/gather/queries/NOTES.md")
    assert not lead_author._is_catalog_template("defender/skills/gather/queries/SCHEMA.md")
    assert not lead_author._is_catalog_template(
        "defender/skills/gather/queries/wazuh/_draft/rough.md"
    )
    assert lead_author._is_catalog_template("defender/skills/gather/queries/wazuh/sub/x.md")
    assert lead_author._is_catalog_template(
        "defender/skills/gather/queries/wazuh/sub/_draft/x.md"
    )


def test_verify_skills_state_rejects_a_promotion_under_a_system_with_no_adapter(
    tmp_git_repo: Path,
):
    ghost = tmp_git_repo / _CATALOG / "ghost"
    ghost.mkdir(parents=True)
    (ghost / "x.md").write_text(query_template("ghost.x", "established"))
    with pytest.raises(lead_author.LeadAuthorError, match="could not be resolved"):
        lead_author._verify_skills_state(
            tmp_git_repo, baseline_stray=[], systems=DECLARED | {"ghost"},
            tree_for=lane_tree_for(tmp_git_repo), git=claim_git(tmp_git_repo)
        )


def test_verify_skills_state_refuses_a_tree_whose_adapters_cannot_be_read(tmp_git_repo: Path):
    adapters = tmp_git_repo / "defender" / "scripts" / "adapters"
    shutil.rmtree(adapters)
    with pytest.raises(lead_author.LeadAuthorError, match="could not be resolved") as exc:
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[], systems=DECLARED,
                                         tree_for=lane_tree_for(tmp_git_repo), git=claim_git(tmp_git_repo))
    assert str(adapters) in str(exc.value), f"the refusal does not name the directory: {exc.value}"
    assert "refusing to commit" in str(exc.value)


def test_verify_skills_state_ignores_baseline_stray(tmp_git_repo: Path):
    """A pre-existing stray captured in baseline_stray isn't blamed on the agent."""
    (tmp_git_repo / "defender" / "other").mkdir(parents=True)
    (tmp_git_repo / "defender" / "other" / "preexisting.md").write_text("x")
    baseline = author_shared.changes_outside(
        tmp_git_repo, lead_author.SKILLS_REL
    )
    assert "defender/other/preexisting.md" in baseline
    changed = lead_author._verify_skills_state(
        tmp_git_repo, baseline_stray=baseline, systems=DECLARED,
        tree_for=lane_tree_for(tmp_git_repo), git=claim_git(tmp_git_repo)
    )
    assert changed == []


def _bypass_tables():
    """Override the two-table read + draft synthesis so the commit/gate flow runs
    against a seeded repo: extract yields one dummy lead, synthesis is a no-op.
    Splatted into ``_deps(...)`` — the agent (faked below) is the only thing that
    touches the corpus."""
    return dict(
        extract=lambda rd: ([], [_executed_lead()]),
        synthesize=lambda executed, skills=None, where=None, catalog=None, systems=None: [],
    )


def test_run_loop_commits_agent_edits(tmp_git_repo: Path, tmp_path: Path):
    """End-to-end: the agent (faked) edits the worktree and runs no git; the loop
    verifies + commits exactly the skills delta with a generated message + writes done."""
    repo = tmp_git_repo
    run_dir = curation_run_dir("lead-run")

    def fake_agent(rd, handoffs, pending, *, box=None):
        (repo / _CATALOG / "wazuh" / "newthing.md").write_text(
            query_template("wazuh.newthing", "established")
        )
        (repo / _CATALOG / "wazuh" / "_draft" / "newthing.md").unlink()
        return 0

    deps = _deps(
        repo,
        **_bypass_tables(),
        invoke_agent=fake_agent,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "wazuh.newthing"}],
        discover_system_drafts=lambda: [],
    )
    head_before = _run_git(repo, "rev-parse", "HEAD").stdout.strip()
    assert lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps) == 0
    head_after = _run_git(repo, "rev-parse", "HEAD").stdout.strip()
    assert head_after != head_before, "the loop should have committed"
    changed = _run_git(repo, "diff", "--name-only", "HEAD~1", "HEAD").stdout.split()
    assert changed
    assert all(p.startswith("defender/skills/") for p in changed)
    assert "defender/skills/gather/queries/wazuh/newthing.md" in changed
    msg = _run_git(repo, "log", "-1", "--format=%B").stdout
    assert "lead-author" in msg
    assert run_dir.name in msg
    assert (run_dir / "lead_author" / "done").is_file()


def test_run_raises_and_skips_commit_on_scope_violation(tmp_git_repo: Path, tmp_path: Path):
    """A stray edit makes the gate raise LeadAuthorError (the drain quarantines the
    marker); the loop commits nothing and writes no done sentinel."""
    repo = tmp_git_repo
    run_dir = curation_run_dir("lead-run")

    stray = _commit_outside(repo)

    def fake_agent(rd, handoffs, pending, *, box=None):
        stray.write_text("stray")
        return 0

    deps = _deps(
        repo,
        **_bypass_tables(),
        invoke_agent=fake_agent,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "x.y"}],
        discover_system_drafts=lambda: [],
    )
    head_before = _run_git(repo, "rev-parse", "HEAD").stdout.strip()
    with pytest.raises(lead_author.LeadAuthorError):
        lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps)
    assert _run_git(repo, "rev-parse", "HEAD").stdout.strip() == head_before
    assert not (run_dir / "lead_author" / "done").is_file()


def test_run_returns_rc2_on_nonzero_agent_exit(tmp_git_repo: Path, tmp_path: Path):
    repo = tmp_git_repo
    run_dir = curation_run_dir("lead-run")
    deps = _deps(
        repo,
        **_bypass_tables(),
        invoke_agent=lambda rd, handoffs, pending, **_kw: 124,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "x.y"}],
        discover_system_drafts=lambda: [],
    )
    head_before = _run_git(repo, "rev-parse", "HEAD").stdout.strip()
    assert lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps) == 2
    assert _run_git(repo, "rev-parse", "HEAD").stdout.strip() == head_before
    assert not (run_dir / "lead_author" / "done").is_file()
    assert not (run_dir / "lead_author" / "failure.txt").exists()


def test_run_loop_clears_drafts_on_discard_and_promote(tmp_git_repo: Path, tmp_path: Path):
    repo = tmp_git_repo
    (repo / _CATALOG / "wazuh" / "_draft" / "olddraft.md").write_text(
        query_template("wazuh.olddraft", "draft")
    )
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "seed second draft")
    run_dir = curation_run_dir("lead-run")

    promoted_est = repo / _CATALOG / "wazuh" / "newthing.md"
    promoted_draft = repo / _CATALOG / "wazuh" / "_draft" / "newthing.md"
    discarded_draft = repo / _CATALOG / "wazuh" / "_draft" / "olddraft.md"

    def fake_agent(rd, handoffs, pending, *, box=None):
        promoted_est.write_text(query_template("wazuh.newthing", "established"))
        promoted_draft.unlink()
        discarded_draft.unlink()
        return 0

    deps = _deps(
        repo,
        **_bypass_tables(),
        invoke_agent=fake_agent,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "wazuh.newthing"}],
        discover_system_drafts=lambda: [],
    )
    assert lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps) == 0
    assert not promoted_draft.exists()
    assert not discarded_draft.exists()
    assert promoted_est.is_file()
    tracked = _run_git(repo, "ls-files", "defender/skills/").stdout.split()
    assert "defender/skills/gather/queries/wazuh/newthing.md" in tracked
    assert "defender/skills/gather/queries/wazuh/_draft/newthing.md" not in tracked
    assert "defender/skills/gather/queries/wazuh/_draft/olddraft.md" not in tracked
    assert (run_dir / "lead_author" / "done").is_file()


def test_run_quarantines_half_promote(tmp_git_repo: Path, tmp_path: Path):
    repo = tmp_git_repo
    run_dir = curation_run_dir("lead-run")

    def fake_agent(rd, handoffs, pending, *, box=None):
        (repo / _CATALOG / "wazuh" / "newthing.md").write_text(
            query_template("wazuh.newthing", "established")
        )
        return 0

    deps = _deps(
        repo,
        **_bypass_tables(),
        invoke_agent=fake_agent,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "wazuh.newthing"}],
        discover_system_drafts=lambda: [],
    )
    head_before = _run_git(repo, "rev-parse", "HEAD").stdout.strip()
    with pytest.raises(lead_author.LeadAuthorError, match="half-promote"):
        lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps)
    assert _run_git(repo, "rev-parse", "HEAD").stdout.strip() == head_before
    assert not (run_dir / "lead_author" / "done").is_file()


def test_run_refuses_a_bare_discard_of_a_draft_it_minted_this_tick(
    tmp_git_repo: Path, tmp_path: Path
):
    repo = tmp_git_repo
    run_dir = curation_run_dir("lead-run")
    (run_dir / "gather_raw").mkdir(parents=True)
    _write_lead_meta(run_dir, "l-001", "probe a brand-new measurement")
    _write_query(run_dir, "l-001", 0, "wazuh.hunt-failed-logins", verb="search",
                 payload_status="ok")

    def fake_agent(rd, handoffs, pending, *, box=None):
        # A bare discard: `rm` the minted draft, attribute it nowhere.
        minted = repo / _CATALOG / "wazuh" / "_draft" / (
            f"{lead_author._draft_basename('wazuh.hunt-failed-logins')}.md"
        )
        assert minted.is_file(), "the mint did not produce the draft this test is about"
        minted.unlink()
        return 0

    deps = replace(
        lead_deps(LoopPaths(repo_root=repo, state_dir=tmp_path / "st")),
        invoke_agent=fake_agent,
    )
    head_before = _run_git(repo, "rev-parse", "HEAD").stdout.strip()
    with pytest.raises(lead_author.LeadAuthorError, match="wazuh.hunt-failed-logins"):
        lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps)
    assert _run_git(repo, "rev-parse", "HEAD").stdout.strip() == head_before
    assert not (run_dir / "lead_author" / "done").is_file()


def test_prepare_handoffs_at_threshold_surfaces_drafts(
    run_dir: Path, monkeypatch, tmp_path
):
    """At-or-above threshold → drafts surface alongside executed handoffs."""
    fake_handoff = [{
        "query_id": "fake.lead", "status": "established",
        "executed_template_path": "defender/skills/gather/queries/fake/lead.md",
        "neighbors": [], "invocations": [],
    }]
    skills = tmp_path / "defender" / "skills"
    (skills / "elastic" / "_draft").mkdir(parents=True)
    drafts = [
        skills / "elastic" / "_draft" / "a.md",
        skills / "elastic" / "_draft" / "b.md",
    ]
    for d in drafts:
        d.write_text("---\nstatus: draft\n---\n")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "2")
    deps = _deps(
        tmp_path,
        extract=lambda rd: ([], [_executed_lead()]),
        build_handoff=lambda rd, ex, jl=None, **_: fake_handoff,
        discover_system_drafts=lambda: drafts,
    )

    handoffs, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc is None
    assert handoffs == fake_handoff
    assert len(pending) == 2
    assert pending[0]["system"] == "elastic"
    assert pending[0]["skill_path"] == "defender/skills/elastic/SKILL.md"


def test_prepare_handoffs_drafts_only_no_executed_proceeds(
    run_dir: Path, monkeypatch, tmp_path
):
    """No executed leads + drafts at threshold → proceed with drafts only."""
    skills = tmp_path / "defender" / "skills"
    (skills / "elastic" / "_draft").mkdir(parents=True)
    drafts = [skills / "elastic" / "_draft" / f"d{i}.md" for i in range(2)]
    for d in drafts:
        d.write_text("---\nstatus: draft\n---\n")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    deps = _deps(tmp_path, discover_system_drafts=lambda: drafts)

    handoffs, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc is None
    assert handoffs == []
    assert len(pending) == 2


def test_prepare_handoffs_both_empty_exits_zero(run_dir: Path, tmp_path: Path):
    """No executed leads AND no pending drafts → early exit 0, no work."""
    deps = _deps(tmp_path, discover_system_drafts=lambda: [])
    handoffs, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc == 0
    assert handoffs == []
    assert pending == []


def _capture_engine(monkeypatch, *, rc: int = 0, raise_exc=None):
    """Patch the in-process engine seam the spawn spine calls. ``_spawn_author_agent`` looks up
    ``run_author_stage`` on the engine module at call time, so patching the module attr is seen. Captures the kwargs the
    spawn forwards to the engine + returns a canned rc / raises."""
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

    monkeypatch.setattr(  # lint-monkeypatch: ok — the spawn spine has no DI seam; capture engine kwargs
        lead_author_engine, "run_author_stage", _fake
    )
    return cap


def test_invoke_agent_pending_drafts_reach_engine_user_prompt(run_dir: Path, monkeypatch):
    cap = _capture_engine(monkeypatch)
    handoffs = [{"query_id": "wazuh.auth-events", "status": "established",
                 "executed_template_path": "defender/skills/gather/queries/wazuh/auth-events.md",
                 "neighbors": [], "invocations": []}]
    pending = [{"draft_path": "defender/skills/elastic/_draft/falco-na.md",
                "system": "elastic",
                "skill_path": "defender/skills/elastic/SKILL.md"}]
    rc = lead_author.invoke_agent(run_dir, handoffs, pending)
    assert rc == 0
    prompt = cap["user_prompt"]
    assert re.search(r"<run-[0-9a-f]+-handoffs>", prompt)
    assert re.search(r"<run-[0-9a-f]+-pending_system_drafts>", prompt)
    assert "elastic/_draft/falco-na.md" in prompt
    assert "skills_dir: defender/skills/" in prompt


def test_extract_carries_error_class(run_dir: Path):
    """An errored query's row back-fills error_class from exit_code, and extract
    threads it onto the ExecutedLead."""
    _write_lead_meta(run_dir, "l-001", "probe")
    _write_query(run_dir, "l-001", 0, "elastic.esql", payload_status="error")
    _, leads = lead_author.extract(run_dir)
    assert leads[0].error_class == "agent-fixable"


def test_collect_general_failures_residue_only(tmp_path: Path, catalog: Path):
    """Only agent-fixable errors that resolve to no template AND are not draft
    candidates are collected — the residue build_handoff would silently drop."""
    run_dir = tmp_path / "run-abc"
    leads = [
        _executed_lead(lead_id="l-001", query_index=0, query_id="elastic.esql",
                       error_class="agent-fixable", payload_digest="exit=1; bad pipe"),
        _executed_lead(lead_id="l-002", query_id="elastic.auth-events",
                       error_class="agent-fixable"),
        _executed_lead(lead_id="l-003", query_id="elastic.new-thing",
                       error_class="agent-fixable"),
        _executed_lead(lead_id="l-004", query_id="elastic.esql", error_class="infra"),
        _executed_lead(lead_id="l-005", query_id="elastic.esql", error_class=None),
    ]
    out = lead_author.collect_general_failures(leads, run_dir,
                                               skills=skills_view(catalog.parents[1]),
    where=catalog.parents[1])
    assert [r["query_id"] for r in out] == ["elastic.esql"]
    r = out[0]
    assert r["pitfall_id"] == "run-abc:l-001:0"
    assert r["source_run"] == "run-abc"
    assert r["system"] == "elastic"
    assert r["error_class"] == "agent-fixable"
    assert r["stderr_digest"] == "exit=1; bad pipe"


def test_collect_and_synthesize_partition_disjointly(tmp_path: Path, catalog: Path):
    """A coined query_id is drafted XOR collected as a general failure, never both
    — the shared _draft_candidate_segments predicate keeps the paths disjoint."""
    leads = [
        _executed_lead(lead_id="l-001", query_id="elastic.new-thing", error_class="agent-fixable"),
        _executed_lead(lead_id="l-002", query_id="elastic.esql", error_class="agent-fixable"),
    ]
    by_id = {t.id for t in lead_author.lead_neighbors.load_catalog(catalog)}
    drafted = {ld.query_id for ld in leads
               if lead_author._draft_candidate_segments(
                   ld.query_id, ld.verb, by_id, row_system=ld.system) is not None}
    collected = {r["query_id"]
                 for r in lead_author.collect_general_failures(
                     leads, tmp_path / "r", skills=skills_view(catalog.parents[1]),
                     where=catalog.parents[1])}
    assert drafted == {"elastic.new-thing"}
    assert collected == {"elastic.esql"}
    assert drafted.isdisjoint(collected)


def test_run_collects_general_failure_before_early_return(tmp_git_repo: Path, tmp_path: Path):
    paths = LoopPaths(repo_root=tmp_git_repo, state_dir=tmp_path / "state")
    deps = replace(
        lead_deps(paths),
        invoke_agent=lambda *a, **k: 0,
    )
    run_dir = curation_run_dir("run-xyz")
    (run_dir / "gather_raw").mkdir(parents=True)
    _write_lead_meta(run_dir, "l-001", "probe")
    _write_query(run_dir, "l-001", 0, "elastic.esql", payload_status="error")

    assert lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps) == 0
    queue = deps.paths.state_root / PITFALLS.queue
    rows = [json.loads(ln) for ln in queue.read_text().splitlines()]
    assert [r["query_id"] for r in rows] == ["elastic.esql"]
    assert rows[0]["error_class"] == "agent-fixable"
    assert (run_dir / "lead_author" / "pitfalls_collected").is_file()

    (run_dir / "lead_author" / "done").unlink()
    assert lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps) == 0
    rows2 = [json.loads(ln) for ln in queue.read_text().splitlines()]
    assert len(rows2) == 1


def test_run_reloads_catalog_after_mint_so_minted_draft_resolves(
    tmp_git_repo: Path, tmp_path: Path
):
    paths = LoopPaths(repo_root=tmp_git_repo, state_dir=tmp_path / "state")
    seen: dict = {}
    deps = replace(
        lead_deps(paths),
        invoke_agent=lambda rd, handoffs, pending, **_kw: seen.update(handoffs=handoffs) or 0,
    )
    run_dir = curation_run_dir("run-mint")
    (run_dir / "gather_raw").mkdir(parents=True)
    _write_lead_meta(run_dir, "l-001", "probe a brand-new verb")
    _write_query(run_dir, "l-001", 0, "wazuh.brandnew", verb="lookup", payload_status="ok")

    assert lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps) == 0
    minted = lead_author._draft_basename("wazuh.brandnew")
    assert (tmp_git_repo / _CATALOG / "wazuh" / "_draft" / f"{minted}.md").is_file()
    assert f"wazuh.{minted}" in {h["query_id"] for h in seen["handoffs"]}


@pytest.mark.parametrize(("case", "changed", "present", "absent"), [
    ("catalog-only", ["defender/skills/gather/queries/wazuh/auth-events.md"],
     ["gather catalog for run-123"], ["system skills"]),

    ("skill-md-only", ["defender/skills/elastic/SKILL.md"],
     ["learning(lead-author): system skills for run-123"], ["gather catalog"]),

    # a system-skill _draft is NOT a catalog path, so it counts as system-skills scope
    ("system-draft-counts-as-skill", ["defender/skills/elastic/_draft/falco-na.md"],
     ["system skills"], ["gather catalog"]),

    ("catalog-and-skill-together",
     ["defender/skills/gather/queries/wazuh/auth-events.md",
      "defender/skills/elastic/SKILL.md"],
     ["gather catalog + system skills"], []),

    # The loop message is built UNCONDITIONALLY, even for an empty change set, so it has to
    # render (no catalog/skill ⇒ 'gather catalog') rather than crash.
    ("empty-change-set", [],
     ["gather catalog for run-123", "\n\nsource-run: run-123\n"], []),
], ids=lambda v: v if isinstance(v, str) and len(v) < 40 and "/" not in v else "")
def test_loop_commit_message_scope_follows_the_changed_paths(case, changed, present, absent):
    """The subject line names the scope the batch actually touched — catalog, system skills,
    or both — and never a scope nothing in `changed` supports."""
    msg = lead_author._loop_commit_message(Path("run-123"), changed)
    for fragment in present:
        assert fragment in msg
    for fragment in absent:
        assert fragment not in msg
