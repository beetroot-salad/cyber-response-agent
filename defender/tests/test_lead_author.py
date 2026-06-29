"""Lead-author driver — extraction shape, handoff shape, lock/sentinel paths.

Scope (minimal, per defender/CLAUDE.md): pin algorithmic invariants that
would silently drift (lead extraction, handoff JSON shape, composite-kind
inference) plus the gating logic that prevents the driver from spawning
``claude`` when it shouldn't. We do NOT exhaustively mock ``claude`` —
the post-flight scope check is shell-and-git logic verifiable by reading
the code.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from defender.learning.leads import lead_author  # type: ignore[import-not-found]
from defender.learning.core.config import LoopPaths  # type: ignore[import-not-found]


def _deps(tmp_path: Path, **overrides):
    """Production lead-author deps rooted at a tmp tree, with leaf collaborators
    overridden by keyword — replaces monkeypatching lead_author's own functions."""
    return replace(lead_author.build_lead_author_deps(LoopPaths(repo_root=tmp_path)), **overrides)


def _executed_lead(**kw):
    """A minimal ``ExecutedLead`` for flow + collection tests. Defaults to an
    ``ok`` lead (``error_class=None``) so ``collect_general_failures`` is a no-op
    unless a test opts into a failure via ``error_class=`` / ``query_id=``."""
    base = dict(
        lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
        query_id="elastic.esql", system="elastic", params={}, raw_command="cli",
        goal_text="", what_to_summarize=(), raw_ref=None,
        payload_status="ok", payload_digest="", error_class=None,
    )
    base.update(kw)
    return lead_author.ExecutedLead(**base)


# ---------------------------------------------------------------------------
# Fixtures — write the two live tables (leads sidecar + queries ledger)
# ---------------------------------------------------------------------------


def _write_lead_meta(run_dir: Path, lead_id: str, goal: str, wts=()) -> None:
    raw = run_dir / "gather_raw"
    raw.mkdir(exist_ok=True)
    (raw / f"{lead_id}.lead.json").write_text(
        json.dumps({"goal": goal, "what_to_summarize": list(wts)})
    )


def _write_query(
    run_dir: Path,
    lead_id: str,
    seq: int,
    query_id: str,
    params: dict | None = None,
    *,
    payload: str | None = "{}",
    payload_status: str = "ok",
    payload_digest: str = "ok digest",
) -> None:
    """Append one queries-table row + (optionally) its by-ref payload."""
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
        "verb": query_id.split(".", 1)[-1],
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
def run_dir(tmp_path: Path) -> Path:
    rd = tmp_path / "test-run-001"
    rd.mkdir()
    (rd / "gather_raw").mkdir()
    return rd


@pytest.fixture
def catalog(tmp_path: Path) -> Path:
    """Self-contained query catalog so build_handoff resolves ids without
    depending on the live, environment-specific on-disk catalog (v2 ships an
    elastic/host-state/cmdb catalog; main ships wazuh). Returns the catalog dir;
    tests pass it as ``build_handoff(..., repo_root=catalog.parent, catalog_dir=catalog)``
    (the read root + the relative-path anchor), so no module-global patch is needed."""
    cat = tmp_path / "queries"
    (cat / "elastic").mkdir(parents=True)
    (cat / "host-state").mkdir(parents=True)
    (cat / "elastic" / "auth-events.md").write_text(
        "---\nid: elastic.auth-events\nstatus: established\n---\n\n"
        "## Goal\nAuthentication events for a host over a window.\n\n"
        "## Query\n\n```\nelastic_cli.py query --window ${window} ${host_clause}\n```\n"
    )
    (cat / "host-state" / "process-list.md").write_text(
        "---\nid: host-state.process-list\nstatus: established\n---\n\n"
        "## Goal\nRunning processes matching a pattern.\n\n"
        "## Query\n\n```\nhost_state_cli.py process-list ${pattern}\n```\n"
    )
    return cat


# ---------------------------------------------------------------------------
# extract()
# ---------------------------------------------------------------------------


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


def test_extract_skips_query_with_no_payload(run_dir: Path):
    # Query row present but payload write failed (payload_path null) — skipped.
    _write_lead_meta(run_dir, "l-001", "x")
    _write_query(run_dir, "l-001", 0, "wazuh.auth-events", payload=None)
    assert lead_author.extract(run_dir)[1] == []


def test_extract_multi_query_skips_missing_payload(run_dir: Path):
    # Multi-query with only first payload present — second skipped.
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


# ---------------------------------------------------------------------------
# build_handoff()
# ---------------------------------------------------------------------------


def test_build_handoff_groups_by_template(run_dir: Path, catalog: Path):
    """Same template invoked across 3 leads → one handoff with 3 invocations."""
    for i in range(3):
        lid = f"l-00{i + 1}"
        _write_lead_meta(run_dir, lid, f"call {i}")
        _write_query(run_dir, lid, 0, "elastic.auth-events", {"host": f"h{i}"},
                     payload_digest=f"call-{i}")
    _, leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(
        run_dir, leads, repo_root=catalog.parent, catalog_dir=catalog
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
    # JSON-serializable so the prompt builder won't choke.
    json.dumps(h)


def test_build_handoff_includes_rendered_query_and_status(run_dir: Path, catalog: Path):
    _write_lead_meta(run_dir, "l-001", "x")
    _write_query(
        run_dir, "l-001", 0, "elastic.auth-events",
        {"host": "bastion-01", "window": "1h"},
        payload_status="suspect_empty",
        payload_digest="0 events; data.srcip is IP-typed",
    )
    _, leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(
        run_dir, leads, repo_root=catalog.parent, catalog_dir=catalog
    )
    assert len(handoffs) == 1
    inv = handoffs[0]["invocations"][0]
    assert inv["payload_status"] == "suspect_empty"
    assert "data.srcip" in inv["payload_digest"]
    assert inv["result_refs"] == ["gather_raw/l-001/0.json"]
    # rendered_query should contain the substituted params from the
    # ## Query body — elastic.auth-events references ${window}; unbound
    # placeholders like ${host_clause} pass through verbatim so the
    # leak is visible.
    assert inv["rendered_query"]  # non-empty
    assert "--window 1h" in inv["rendered_query"]
    assert "${host_clause}" in inv["rendered_query"]


def test_build_handoff_surfaces_literal_esql_query(run_dir: Path, catalog: Path):
    """For an ES|QL invocation the bindings live inside arg0, not as named
    params — so the handoff carries the literal pipe as `executed_query`
    (the canonical record), not a `${param}` re-render that drops the values."""
    pipe = 'FROM logs-system.auth-* | WHERE host.name == "db-1" | STATS c = COUNT(*)'
    _write_lead_meta(run_dir, "l-001", "x")
    _write_query(run_dir, "l-001", 0, "elastic.auth-events", {"arg0": pipe})
    _, leads = lead_author.extract(run_dir)
    inv = lead_author.build_handoff(
        run_dir, leads, repo_root=catalog.parent, catalog_dir=catalog
    )[0]["invocations"][0]
    assert inv["executed_query"] == pipe


def test_build_handoff_drops_unresolved_query_id(run_dir: Path, catalog: Path):
    """Unresolved query_id ⇒ skip with a corpus-health warning, don't crash."""
    _write_lead_meta(run_dir, "l-001", "novel")
    _write_query(run_dir, "l-001", 0, "elastic.does-not-exist")
    _write_lead_meta(run_dir, "l-002", "real one")
    _write_query(run_dir, "l-002", 0, "elastic.auth-events")
    _, leads = lead_author.extract(run_dir)
    assert len(leads) == 2
    handoffs = lead_author.build_handoff(
        run_dir, leads, repo_root=catalog.parent, catalog_dir=catalog
    )
    # Only the resolved lead survives.
    assert len(handoffs) == 1
    assert handoffs[0]["query_id"] == "elastic.auth-events"


def test_build_handoff_drops_ad_hoc_empty_query_id(run_dir: Path):
    _write_lead_meta(run_dir, "l-001", "ad-hoc")
    _write_query(run_dir, "l-001", 0, "")
    _, leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(run_dir, leads)
    assert handoffs == []


def test_build_handoff_co_dispatched_with_for_join(run_dir: Path, catalog: Path):
    """Cross-system join: each invocation lists its sibling template path."""
    _write_lead_meta(run_dir, "l-001", "cross-system")
    _write_query(run_dir, "l-001", 0, "elastic.auth-events")
    _write_query(run_dir, "l-001", 1, "host-state.process-list", {"pattern": "x"})
    _, leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(
        run_dir, leads, repo_root=catalog.parent, catalog_dir=catalog
    )
    # Two handoffs (one per template).
    assert len(handoffs) == 2
    by_id = {h["query_id"]: h for h in handoffs}
    auth_inv = by_id["elastic.auth-events"]["invocations"][0]
    assert auth_inv["composite_kind"] == "join"
    assert any("host-state/process-list.md" in p for p in auth_inv["co_dispatched_with"])


# ---------------------------------------------------------------------------
# Gating: locks, sentinels, brakes
# ---------------------------------------------------------------------------


def _claude_should_not_be_called(*args, **kwargs):
    raise AssertionError("claude was spawned despite gating check")


def test_run_missing_run_dir(tmp_path: Path):
    assert lead_author.run(tmp_path / "nope") == 2


def test_run_held_queue_lock_returns_zero(run_dir: Path):
    # Pretend the queue lock is held by injecting an acquire that returns None.
    deps = _deps(
        run_dir.parent,
        acquire_queue_lock=lambda: None,
        invoke_agent=_claude_should_not_be_called,
    )
    assert lead_author.run(run_dir, deps=deps) == 0


def test_run_done_sentinel_short_circuits(run_dir: Path):
    state = run_dir / "lead_author"
    state.mkdir()
    (state / "done").write_text("ok")
    deps = _deps(
        run_dir.parent,
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
        invoke_agent=_claude_should_not_be_called,
    )
    assert lead_author.run(run_dir, deps=deps) == 0


# ---------------------------------------------------------------------------
# path classifiers
# ---------------------------------------------------------------------------


def test_under_draft_classifier():
    assert lead_author._under_draft("defender/skills/gather/queries/wazuh/_draft/x.md")
    assert lead_author._under_draft("defender/skills/gather/queries/host-query/_draft/y.md")
    assert not lead_author._under_draft("defender/skills/gather/queries/wazuh/auth-events.md")
    assert not lead_author._under_draft("defender/lessons/x.md")


def test_is_system_skill_md_classifier():
    assert lead_author._is_system_skill_md("defender/skills/elastic/SKILL.md")
    assert lead_author._is_system_skill_md("defender/skills/wazuh/SKILL.md")
    # Catalog templates are NOT system-skill SKILL.md files.
    assert not lead_author._is_system_skill_md(
        "defender/skills/gather/queries/wazuh/auth-events.md"
    )
    # The schema doc lives at depth 3, not 2.
    assert not lead_author._is_system_skill_md(
        "defender/skills/gather/queries/SCHEMA.md"
    )
    # Drafts inside a system skill dir are not the skill itself.
    assert not lead_author._is_system_skill_md(
        "defender/skills/elastic/_draft/foo.md"
    )


def test_is_system_skill_draft_classifier():
    assert lead_author._is_system_skill_draft("defender/skills/elastic/_draft/foo.md")
    assert lead_author._is_system_skill_draft("defender/skills/cmdb/_draft/bar.md")
    # Catalog drafts (two segments deeper) are NOT system-skill drafts.
    assert not lead_author._is_system_skill_draft(
        "defender/skills/gather/queries/elastic/_draft/foo.md"
    )
    # SKILL.md is not a draft.
    assert not lead_author._is_system_skill_draft("defender/skills/elastic/SKILL.md")


def test_is_in_scope_covers_both_surfaces():
    assert lead_author._is_in_scope("defender/skills/gather/queries/wazuh/auth-events.md")
    assert lead_author._is_in_scope("defender/skills/elastic/SKILL.md")
    assert lead_author._is_in_scope("defender/skills/elastic/_draft/foo.md")
    assert not lead_author._is_in_scope("defender/lessons/x.md")
    assert not lead_author._is_in_scope("defender/other/stray.md")


def test_discover_system_drafts_finds_files_excluding_readme(tmp_path):
    """README.md and _TEMPLATE.md are surface declarations, not drafts."""
    skills = tmp_path / "defender" / "skills"
    (skills / "elastic" / "_draft").mkdir(parents=True)
    (skills / "elastic" / "_draft" / "README.md").write_text("surface declaration\n")
    (skills / "elastic" / "_draft" / "real-draft.md").write_text("---\nstatus: draft\n---\n")
    (skills / "elastic" / "SKILL.md").write_text("# elastic\n")
    # Another system with no drafts — must be ignored.
    (skills / "wazuh").mkdir()
    (skills / "wazuh" / "SKILL.md").write_text("# wazuh\n")
    # A nested catalog draft must NOT be picked up (two levels deeper).
    (skills / "gather" / "queries" / "elastic" / "_draft").mkdir(parents=True)
    (skills / "gather" / "queries" / "elastic" / "_draft" / "ignore.md").write_text("ignore\n")
    # _TEMPLATE.md in a draft dir should be skipped.
    (skills / "cmdb" / "_draft").mkdir(parents=True)
    (skills / "cmdb" / "_draft" / "_TEMPLATE.md").write_text("template\n")

    found = lead_author.discover_system_drafts(skills_dir=skills)
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


# ---------------------------------------------------------------------------
# _verify_skills_state — loop-side scope gate over the agent's working-tree edits
# ---------------------------------------------------------------------------


def _run_git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd,
                          capture_output=True, text=True, check=True)


_CATALOG = "defender/skills/gather/queries"


@pytest.fixture
def tmp_git_repo(tmp_path: Path) -> Path:
    """A clean git repo with a seeded skills tree (committed) — stands in for a fresh
    ``lead-author/<id>`` worktree. The agent runs no git, so tests then make *working-tree*
    edits and call ``_verify_skills_state`` / drive ``run`` over them, asserting the loop's
    gate + commit behavior."""
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


def test_verify_skills_state_accepts_in_scope_edits(tmp_git_repo: Path):
    """Fold an established template, promote a draft (write established + rm draft), and
    lift a system skill (edit SKILL.md + rm draft) — all in-scope; returns changed paths."""
    repo = tmp_git_repo
    (repo / _CATALOG / "wazuh" / "auth-events.md").write_text(
        "---\nid: wazuh.auth-events\nstatus: established\n---\n# folded\n"
    )
    (repo / _CATALOG / "wazuh" / "newthing.md").write_text(
        "---\nid: wazuh.newthing\nstatus: established\n---\n"
    )
    (repo / _CATALOG / "wazuh" / "_draft" / "newthing.md").unlink()
    skill = repo / "defender" / "skills" / "elastic" / "SKILL.md"
    skill.write_text(skill.read_text() + "\n## Falco quirk\nworkaround\n")
    (repo / "defender" / "skills" / "elastic" / "_draft" / "falco-na.md").unlink()

    changed = lead_author._verify_skills_state(repo, baseline_stray=[])
    assert "defender/skills/gather/queries/wazuh/auth-events.md" in changed
    assert "defender/skills/gather/queries/wazuh/newthing.md" in changed
    assert "defender/skills/elastic/SKILL.md" in changed


def test_verify_skills_state_rejects_stray_outside_skills(tmp_git_repo: Path):
    (tmp_git_repo / "defender" / "other").mkdir(parents=True)
    (tmp_git_repo / "defender" / "other" / "stray.md").write_text("stray")
    with pytest.raises(lead_author.LeadAuthorError, match="outside"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[])


def test_verify_skills_state_rejects_non_md_under_skills(tmp_git_repo: Path):
    """A non-*.md file under defender/skills/ is a stray (corpus is *.md)."""
    (tmp_git_repo / "defender" / "skills" / "junk.json").write_text("{}")
    with pytest.raises(lead_author.LeadAuthorError, match="outside"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[])


def test_verify_skills_state_rejects_out_of_scope_skills_md(tmp_git_repo: Path):
    """A skills *.md that is neither catalog, SKILL.md, nor _draft is out of scope."""
    (tmp_git_repo / "defender" / "skills" / "elastic" / "execution.md").write_text("x")
    with pytest.raises(lead_author.LeadAuthorError, match="out-of-scope"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[])


def test_verify_skills_state_rejects_established_deletion(tmp_git_repo: Path):
    (tmp_git_repo / _CATALOG / "wazuh" / "auth-events.md").unlink()
    with pytest.raises(lead_author.LeadAuthorError, match="delete-prohibition"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[])


def test_verify_skills_state_rejects_skill_md_deletion(tmp_git_repo: Path):
    (tmp_git_repo / "defender" / "skills" / "elastic" / "SKILL.md").unlink()
    with pytest.raises(lead_author.LeadAuthorError, match="delete-prohibition"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[])


def test_verify_skills_state_rejects_draft_readme_mutation(tmp_git_repo: Path):
    readme = tmp_git_repo / "defender" / "skills" / "elastic" / "_draft" / "README.md"
    readme.write_text(readme.read_text() + "\nstomped\n")
    with pytest.raises(lead_author.LeadAuthorError, match="protected surface"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[])


def test_verify_skills_state_rejects_schema_mutation(tmp_git_repo: Path):
    schema = tmp_git_repo / _CATALOG / "SCHEMA.md"
    schema.write_text(schema.read_text() + "\nstomped\n")
    with pytest.raises(lead_author.LeadAuthorError, match="protected surface"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[])


def test_verify_skills_state_accepts_draft_discard(tmp_git_repo: Path):
    (tmp_git_repo / _CATALOG / "wazuh" / "_draft" / "newthing.md").unlink()
    changed = lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[])
    assert changed == ["defender/skills/gather/queries/wazuh/_draft/newthing.md"]


def test_verify_skills_state_rejects_half_promote(tmp_git_repo: Path):
    """A promote that writes the established template but never ``rm``s its ``_draft/`` twin
    leaves both on disk. The surviving draft is unchanged ⇒ not in ``git status`` ⇒ the
    records-only checks can't see it; the filesystem twin probe must catch the half-promote
    rather than letting the loop commit established + draft together."""
    (tmp_git_repo / _CATALOG / "wazuh" / "newthing.md").write_text(
        "---\nid: wazuh.newthing\nstatus: established\n---\n"
    )
    # The promote's ``rm`` of _draft/newthing.md is deliberately omitted.
    with pytest.raises(lead_author.LeadAuthorError, match="half-promote"):
        lead_author._verify_skills_state(tmp_git_repo, baseline_stray=[])


def test_verify_skills_state_ignores_baseline_stray(tmp_git_repo: Path):
    """A pre-existing stray captured in baseline_stray isn't blamed on the agent."""
    (tmp_git_repo / "defender" / "other").mkdir(parents=True)
    (tmp_git_repo / "defender" / "other" / "preexisting.md").write_text("x")
    baseline = lead_author._author_shared.changes_outside(
        tmp_git_repo, lead_author.SKILLS_REL
    )
    assert "defender/other/preexisting.md" in baseline
    changed = lead_author._verify_skills_state(tmp_git_repo, baseline_stray=baseline)
    assert changed == []


# ---------------------------------------------------------------------------
# loop is sole committer — run() drives _verify_skills_state + commit_corpus
# ---------------------------------------------------------------------------


def _bypass_tables():
    """Override the two-table read + draft synthesis so the commit/gate flow runs
    against a seeded repo: extract yields one dummy lead, synthesis is a no-op.
    Splatted into ``_deps(...)`` — the agent (faked below) is the only thing that
    touches the corpus."""
    return dict(
        extract=lambda rd: ([], [_executed_lead()]),
        synthesize=lambda executed, catalog_dir=None, catalog=None: [],
    )


def test_run_loop_commits_agent_edits(tmp_git_repo: Path, tmp_path: Path):
    """End-to-end: the agent (faked) edits the worktree and runs no git; the loop
    verifies + commits exactly the skills delta with a generated message + writes done."""
    repo = tmp_git_repo
    run_dir = tmp_path / "lead-run"
    run_dir.mkdir()

    def fake_agent(rd, handoffs, pending):
        (repo / _CATALOG / "wazuh" / "newthing.md").write_text(
            "---\nid: wazuh.newthing\nstatus: established\n---\n"
        )
        (repo / _CATALOG / "wazuh" / "_draft" / "newthing.md").unlink()
        return 0

    deps = _deps(
        repo,
        **_bypass_tables(),
        invoke_agent=fake_agent,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "wazuh.newthing"}],
        discover_system_drafts=lambda: [],
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
    )
    head_before = _run_git(repo, "rev-parse", "HEAD").stdout.strip()
    assert lead_author.run(run_dir, deps=deps) == 0
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
    run_dir = tmp_path / "lead-run"
    run_dir.mkdir()

    def fake_agent(rd, handoffs, pending):
        (repo / "defender" / "other").mkdir(parents=True, exist_ok=True)
        (repo / "defender" / "other" / "stray.md").write_text("stray")
        return 0

    deps = _deps(
        repo,
        **_bypass_tables(),
        invoke_agent=fake_agent,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "x.y"}],
        discover_system_drafts=lambda: [],
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
    )
    head_before = _run_git(repo, "rev-parse", "HEAD").stdout.strip()
    with pytest.raises(lead_author.LeadAuthorError):
        lead_author.run(run_dir, deps=deps)
    assert _run_git(repo, "rev-parse", "HEAD").stdout.strip() == head_before
    assert not (run_dir / "lead_author" / "done").is_file()


def test_run_returns_rc2_on_nonzero_agent_exit(tmp_git_repo: Path, tmp_path: Path):
    """A non-zero agent exit (crash/timeout) makes ``run`` return 2 — the drain
    quarantines the marker. The loop commits nothing, writes no done sentinel, and
    (post-#426) writes no ``failure.txt`` brake (quarantine is the sole surfacing)."""
    repo = tmp_git_repo
    run_dir = tmp_path / "lead-run"
    run_dir.mkdir()
    deps = _deps(
        repo,
        **_bypass_tables(),
        invoke_agent=lambda rd, handoffs, pending: 124,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "x.y"}],
        discover_system_drafts=lambda: [],
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
    )
    head_before = _run_git(repo, "rev-parse", "HEAD").stdout.strip()
    assert lead_author.run(run_dir, deps=deps) == 2
    assert _run_git(repo, "rev-parse", "HEAD").stdout.strip() == head_before
    assert not (run_dir / "lead_author" / "done").is_file()
    assert not (run_dir / "lead_author" / "failure.txt").exists()


def test_run_loop_clears_drafts_on_discard_and_promote(tmp_git_repo: Path, tmp_path: Path):
    """The fake-LLM stand-in for the live ``--lead-author-drain`` check: the agent does a
    discard (``rm`` a draft) AND a promote (write established + ``rm`` its draft) in the
    worktree; after ``run`` the loop has committed and *both* draft files are actually gone
    — neither left on disk nor tracked — with the promoted established template present and
    no established+draft duplicate. This is what the live ``rm``-under-allowlist run was to
    confirm; only the real Claude Code Bash matcher is out of frame here (the grant uses the
    documented ``:*`` form), the loop's commit/clear logic is end-to-end."""
    repo = tmp_git_repo
    # A second catalog draft to discard — committed, so it stands in for a prior tick's
    # tracked draft (the case the records-only gate can't see if its `rm` is skipped).
    (repo / _CATALOG / "wazuh" / "_draft" / "olddraft.md").write_text(
        "---\nid: wazuh.olddraft\nstatus: draft\n---\n"
    )
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "seed second draft")
    run_dir = tmp_path / "lead-run"
    run_dir.mkdir()

    promoted_est = repo / _CATALOG / "wazuh" / "newthing.md"
    promoted_draft = repo / _CATALOG / "wazuh" / "_draft" / "newthing.md"
    discarded_draft = repo / _CATALOG / "wazuh" / "_draft" / "olddraft.md"

    def fake_agent(rd, handoffs, pending):
        promoted_est.write_text("---\nid: wazuh.newthing\nstatus: established\n---\n")
        promoted_draft.unlink()   # promote's rm
        discarded_draft.unlink()  # discard's rm
        return 0

    deps = _deps(
        repo,
        **_bypass_tables(),
        invoke_agent=fake_agent,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "wazuh.newthing"}],
        discover_system_drafts=lambda: [],
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
    )
    assert lead_author.run(run_dir, deps=deps) == 0
    # Drafts actually gone (the live check's core assertion); established remains.
    assert not promoted_draft.exists()
    assert not discarded_draft.exists()
    assert promoted_est.is_file()
    tracked = _run_git(repo, "ls-files", "defender/skills/").stdout.split()
    assert "defender/skills/gather/queries/wazuh/newthing.md" in tracked
    assert "defender/skills/gather/queries/wazuh/_draft/newthing.md" not in tracked
    assert "defender/skills/gather/queries/wazuh/_draft/olddraft.md" not in tracked
    assert (run_dir / "lead_author" / "done").is_file()


def test_run_quarantines_half_promote(tmp_git_repo: Path, tmp_path: Path):
    """End-to-end: the agent writes a promote's established template but forgets the draft
    ``rm`` (the silent-loss case A1's matcher fix can't prevent if the model omits it). The
    loop's half-promote gate raises through ``run`` → no commit, no ``done`` → the drain
    quarantines the marker instead of committing established + draft together."""
    repo = tmp_git_repo
    run_dir = tmp_path / "lead-run"
    run_dir.mkdir()

    def fake_agent(rd, handoffs, pending):
        (repo / _CATALOG / "wazuh" / "newthing.md").write_text(
            "---\nid: wazuh.newthing\nstatus: established\n---\n"
        )  # _draft/newthing.md deliberately left in place
        return 0

    deps = _deps(
        repo,
        **_bypass_tables(),
        invoke_agent=fake_agent,
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "wazuh.newthing"}],
        discover_system_drafts=lambda: [],
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
    )
    head_before = _run_git(repo, "rev-parse", "HEAD").stdout.strip()
    with pytest.raises(lead_author.LeadAuthorError, match="half-promote"):
        lead_author.run(run_dir, deps=deps)
    assert _run_git(repo, "rev-parse", "HEAD").stdout.strip() == head_before
    assert not (run_dir / "lead_author" / "done").is_file()


# ---------------------------------------------------------------------------
# _prepare_handoffs — lift threshold + early-exit gates
# ---------------------------------------------------------------------------


def test_prepare_handoffs_below_lift_threshold_returns_empty_drafts(
    run_dir: Path, monkeypatch
):
    """Pending drafts below threshold are silenced; executed handoffs unaffected.

    Stubs out the executed-flow primitives so this test exercises only the
    threshold gate, independent of which query templates exist in the catalog.
    """
    fake_executed = [_executed_lead()]
    fake_handoff = [{
        "query_id": "fake.lead", "status": "established",
        "executed_template_path": "defender/skills/gather/queries/fake/lead.md",
        "neighbors": [], "invocations": [],
    }]
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5")
    deps = _deps(
        run_dir.parent,
        extract=lambda rd: ([], fake_executed),
        build_handoff=lambda rd, ex, jl=None, **_: fake_handoff,
        discover_system_drafts=lambda: [Path("/fake/a.md"), Path("/fake/b.md")],
    )
    handoffs, drafts, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc is None
    assert handoffs == fake_handoff
    assert drafts == []


def test_prepare_handoffs_at_threshold_surfaces_drafts(
    run_dir: Path, monkeypatch, tmp_path
):
    """At-or-above threshold → drafts surface alongside executed handoffs."""
    fake_handoff = [{
        "query_id": "fake.lead", "status": "established",
        "executed_template_path": "defender/skills/gather/queries/fake/lead.md",
        "neighbors": [], "invocations": [],
    }]
    # Seed two real draft files so build_system_draft_handoffs can compute
    # repo-relative paths (against deps.paths.repo_root=tmp_path).
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
    # No tables written — extract() returns [].
    skills = tmp_path / "defender" / "skills"
    (skills / "elastic" / "_draft").mkdir(parents=True)
    drafts = [skills / "elastic" / "_draft" / f"d{i}.md" for i in range(2)]
    for d in drafts:
        d.write_text("---\nstatus: draft\n---\n")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    # extract stays the real impl (no tables in run_dir → []); only discover is faked.
    deps = _deps(tmp_path, discover_system_drafts=lambda: drafts)

    handoffs, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc is None
    assert handoffs == []
    assert len(pending) == 2


def test_prepare_handoffs_both_empty_exits_zero(run_dir: Path):
    """No executed leads AND no pending drafts → early exit 0, no work."""
    deps = _deps(run_dir.parent, discover_system_drafts=lambda: [])
    handoffs, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc == 0
    assert handoffs == []
    assert pending == []


def test_invoke_agent_includes_pending_drafts_in_prompt(
    run_dir: Path, monkeypatch
):
    """User prompt must carry the new pending_system_drafts section."""
    captured: dict = {}

    # invoke_agent routes through the shared runner (#373); capture the prompt at
    # that seam instead of stubbing subprocess.run, which it no longer calls.
    def _fake_raw(options, user_prompt, log_fn):
        captured["input"] = user_prompt
        return 0, ""

    monkeypatch.setattr(
        lead_author._author_runner, "invoke_claude_print_raw", _fake_raw
    )
    handoffs = [{"query_id": "wazuh.auth-events", "status": "established",
                 "executed_template_path": "defender/skills/gather/queries/wazuh/auth-events.md",
                 "neighbors": [], "invocations": []}]
    pending = [{"draft_path": "defender/skills/elastic/_draft/falco-na.md",
                "system": "elastic",
                "skill_path": "defender/skills/elastic/SKILL.md"}]
    rc = lead_author.invoke_agent(run_dir, handoffs, pending)
    assert rc == 0
    prompt = captured["input"]
    assert "executed_template_handoffs (1)" in prompt
    assert "pending_system_drafts (1)" in prompt
    assert "elastic/_draft/falco-na.md" in prompt
    assert "skills_dir: defender/skills/" in prompt


# ---------------------------------------------------------------------------
# General-failure collection (Stage 1) + execution.md curation mode (Stage 2)
# ---------------------------------------------------------------------------


def test_extract_carries_error_class(run_dir: Path):
    """An errored query's row back-fills error_class from exit_code, and extract
    threads it onto the ExecutedLead."""
    _write_lead_meta(run_dir, "l-001", "probe")
    _write_query(run_dir, "l-001", 0, "elastic.esql", payload_status="error")  # exit 1
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
                       error_class="agent-fixable"),        # template failure → existing fold
        _executed_lead(lead_id="l-003", query_id="elastic.new-thing",
                       error_class="agent-fixable"),        # draft candidate → becomes a draft
        _executed_lead(lead_id="l-004", query_id="elastic.esql", error_class="infra"),  # down system
        _executed_lead(lead_id="l-005", query_id="elastic.esql", error_class=None),     # ok
    ]
    out = lead_author.collect_general_failures(leads, run_dir, catalog_dir=catalog)
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
               if lead_author._draft_candidate_segments(ld.query_id, by_id) is not None}
    collected = {r["query_id"]
                 for r in lead_author.collect_general_failures(leads, tmp_path / "r", catalog_dir=catalog)}
    assert drafted == {"elastic.new-thing"}
    assert collected == {"elastic.esql"}
    assert drafted.isdisjoint(collected)


def test_run_collects_general_failure_before_early_return(tmp_git_repo: Path, tmp_path: Path):
    """The collection runs before _prepare_handoffs' done-sentinel early-return (the
    all-unresolved case is the very source of general failures), lands in the central
    queue, and the pitfalls_collected sentinel makes a re-run idempotent. repo_root is
    a real git repo (the tick runs `git status` for its stray baseline); the queue
    resolves to an out-of-repo state dir."""
    paths = LoopPaths(repo_root=tmp_git_repo, state_dir=tmp_path / "state")
    deps = replace(
        lead_author.build_lead_author_deps(paths),
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
        invoke_agent=lambda *a, **k: 0,
    )
    run_dir = tmp_path / "run-xyz"
    (run_dir / "gather_raw").mkdir(parents=True)
    _write_lead_meta(run_dir, "l-001", "probe")
    _write_query(run_dir, "l-001", 0, "elastic.esql", payload_status="error")  # general failure

    assert lead_author.run(run_dir, deps=deps) == 0
    queue = deps.paths.pitfalls.file
    rows = [json.loads(ln) for ln in queue.read_text().splitlines()]
    assert [r["query_id"] for r in rows] == ["elastic.esql"]
    assert rows[0]["error_class"] == "agent-fixable"
    assert (run_dir / "lead_author" / "pitfalls_collected").is_file()

    # Idempotent: clear `done` and re-run — the collected sentinel blocks a re-append.
    (run_dir / "lead_author" / "done").unlink()
    assert lead_author.run(run_dir, deps=deps) == 0
    rows2 = [json.loads(ln) for ln in queue.read_text().splitlines()]
    assert len(rows2) == 1


def test_run_reloads_catalog_after_mint_so_minted_draft_resolves(
    tmp_git_repo: Path, tmp_path: Path
):
    """The reload-on-mint hinge: when synthesize_drafts mints a draft for an
    uncatalogued verb this tick, `_run_locked` refreshes the once-loaded catalog so
    build_handoff (the post-synthesis consumer) sees the new `_draft/` and the
    just-minted query_id resolves into a handoff (the WARN-and-draft path) instead of
    being dropped (WARN-and-drop). Uses production synthesize + build_handoff, so it
    guards against a regression that reused the stale pre-synthesis snapshot — which
    would silently drop every just-minted draft's handoff."""
    paths = LoopPaths(repo_root=tmp_git_repo, state_dir=tmp_path / "state")
    seen: dict = {}
    deps = replace(
        lead_author.build_lead_author_deps(paths),
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda fh: None,
        invoke_agent=lambda rd, handoffs, pending: seen.update(handoffs=handoffs) or 0,
    )
    run_dir = tmp_path / "run-mint"
    (run_dir / "gather_raw").mkdir(parents=True)
    _write_lead_meta(run_dir, "l-001", "probe a brand-new verb")
    _write_query(run_dir, "l-001", 0, "wazuh.brandnew", payload_status="ok")

    assert lead_author.run(run_dir, deps=deps) == 0
    # synthesize minted the draft on disk this tick...
    assert (tmp_git_repo / _CATALOG / "wazuh" / "_draft" / "brandnew.md").is_file()
    # ...and build_handoff, seeing the refreshed (post-synthesis) catalog, resolved the
    # just-minted id into a handoff rather than WARN-and-dropping it.
    assert "wazuh.brandnew" in {h["query_id"] for h in seen["handoffs"]}


def test_verify_pitfalls_state_accepts_execution_md(tmp_git_repo: Path):
    (tmp_git_repo / "defender" / "skills" / "elastic" / "execution.md").write_text(
        "# elastic\n## Common pitfalls\n- use `index=windows`, not `index:windows`\n"
    )
    changed = lead_author._verify_pitfalls_state(tmp_git_repo, baseline_stray=[])
    assert changed == ["defender/skills/elastic/execution.md"]


def test_verify_pitfalls_state_rejects_non_execution_md(tmp_git_repo: Path):
    """A SKILL.md edit is in lead-author scope but NOT pitfalls scope — rejected."""
    skill = tmp_git_repo / "defender" / "skills" / "elastic" / "SKILL.md"
    skill.write_text(skill.read_text() + "\nedit\n")
    with pytest.raises(lead_author.LeadAuthorError, match="non-execution.md"):
        lead_author._verify_pitfalls_state(tmp_git_repo, baseline_stray=[])


def test_verify_pitfalls_state_rejects_stray(tmp_git_repo: Path):
    (tmp_git_repo / "defender" / "other").mkdir(parents=True)
    (tmp_git_repo / "defender" / "other" / "stray.md").write_text("x")
    with pytest.raises(lead_author.LeadAuthorError, match="outside"):
        lead_author._verify_pitfalls_state(tmp_git_repo, baseline_stray=[])


def test_verify_pitfalls_state_rejects_deletion(tmp_git_repo: Path):
    ex = tmp_git_repo / "defender" / "skills" / "elastic" / "execution.md"
    ex.write_text("# e\n")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "add exec")
    ex.unlink()
    with pytest.raises(lead_author.LeadAuthorError, match="deleted"):
        lead_author._verify_pitfalls_state(tmp_git_repo, baseline_stray=[])


def _seed_pitfalls(paths, n: int) -> None:
    from defender.learning.core import persist
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
    rc = lead_author.run_pitfalls(paths=paths, invoke=lambda *a, **k: called.append(1) or 0)
    assert rc == 0
    assert called == []                                   # no spawn
    assert len(lead_author._loop_persist.read_pitfalls(paths)) == 2  # queue intact


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

    rc = lead_author.run_pitfalls(paths=paths, invoke=fake_invoke)
    assert rc == 0
    # committed to defender/skills/ in the worktree
    log = _run_git(tmp_git_repo, "log", "--oneline", "-1").stdout
    assert "execution.md pitfalls" in log
    # queue drained, consumed file records the batch
    assert lead_author._loop_persist.read_pitfalls(paths) == []
    consumed = [json.loads(ln) for ln in paths.pitfalls.consumed.read_text().splitlines()]
    assert {c["pitfall_id"] for c in consumed} == {"r:l-000:0", "r:l-001:0"}


def test_run_pitfalls_no_edit_tick_still_rotates(tmp_git_repo: Path, tmp_path: Path, monkeypatch):
    """A curator that legitimately makes no edits (every failure already documented
    / too thin to fix — a valid tick per the prompt) must still drain the batch.
    Otherwise the queue stays >= threshold and re-spawns the curator forever."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    paths = LoopPaths(repo_root=tmp_git_repo, state_dir=tmp_path / "state")
    _seed_pitfalls(paths, 2)
    rc = lead_author.run_pitfalls(paths=paths, invoke=lambda handoffs, *, repo_root: 0)
    assert rc == 0
    assert lead_author._loop_persist.read_pitfalls(paths) == []      # drained, not stuck
    assert _run_git(tmp_git_repo, "status", "--porcelain").stdout == ""  # no commit/edits


def test_run_pitfalls_all_systemless_drops_batch_without_spawn(tmp_git_repo: Path, tmp_path: Path, monkeypatch):
    """A batch whose rows all carry no system can't be folded into any execution.md;
    run_pitfalls drops it without spawning the curator instead of leaving it stuck at
    threshold and re-waking the drain every tick."""
    from defender.learning.core import persist
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    paths = LoopPaths(repo_root=tmp_git_repo, state_dir=tmp_path / "state")
    persist.append_pitfalls(
        [{"pitfall_id": f"r:{i}", "system": ""} for i in range(2)], paths=paths
    )
    called: list[int] = []
    rc = lead_author.run_pitfalls(paths=paths, invoke=lambda *a, **k: called.append(1) or 0)
    assert rc == 0
    assert called == []                                              # no curator spawn
    assert lead_author._loop_persist.read_pitfalls(paths) == []      # dropped, not stuck


def test_collect_general_failures_skips_systemless(tmp_path: Path, catalog: Path):
    """A failure with a blank system is never collected — it has no
    defender/skills/{system}/execution.md to fold into."""
    leads = [
        _executed_lead(lead_id="l-001", query_id="elastic.esql", system="",
                       error_class="agent-fixable"),
    ]
    out = lead_author.collect_general_failures(leads, tmp_path / "r", catalog_dir=catalog)
    assert out == []
