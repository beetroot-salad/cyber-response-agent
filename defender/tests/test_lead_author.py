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
from pathlib import Path

import pytest

import lead_author  # type: ignore[import-not-found]
import lead_neighbors  # type: ignore[import-not-found]


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
def catalog(tmp_path: Path, monkeypatch) -> Path:
    """Self-contained query catalog so build_handoff resolves ids without
    depending on the live, environment-specific on-disk catalog (v2 ships an
    elastic/host-state/cmdb catalog; main ships wazuh). Points both
    CATALOG_ROOT and REPO_ROOT at the temp tree (build_handoff renders
    template paths relative to REPO_ROOT)."""
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
    monkeypatch.setattr(lead_neighbors, "CATALOG_ROOT", cat)
    monkeypatch.setattr(lead_author.lead_neighbors, "CATALOG_ROOT", cat)
    monkeypatch.setattr(lead_author, "CATALOG_DIR", cat)
    monkeypatch.setattr(lead_author, "REPO_ROOT", tmp_path)
    return cat


# ---------------------------------------------------------------------------
# extract()
# ---------------------------------------------------------------------------


def test_extract_single_query_per_entry(run_dir: Path):
    _write_lead_meta(run_dir, "l-001", "list auth events", ["src_ip", "user"])
    _write_query(run_dir, "l-001", 0, "wazuh.auth-events", {"host": "h1", "window": "1h"})
    leads = lead_author.extract(run_dir)
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
    leads = lead_author.extract(run_dir)
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
    assert lead_author.extract(run_dir) == []


def test_extract_multi_query_skips_missing_payload(run_dir: Path):
    # Multi-query with only first payload present — second skipped.
    _write_lead_meta(run_dir, "l-001", "partial fan-out")
    _write_query(run_dir, "l-001", 0, "wazuh.auth-events")
    _write_query(run_dir, "l-001", 1, "wazuh.sudo-commands", payload=None)
    leads = lead_author.extract(run_dir)
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
    leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(run_dir, leads)
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
    leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(run_dir, leads)
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


def test_build_handoff_drops_unresolved_query_id(run_dir: Path, catalog: Path):
    """Unresolved query_id ⇒ skip with a corpus-health warning, don't crash."""
    _write_lead_meta(run_dir, "l-001", "novel")
    _write_query(run_dir, "l-001", 0, "elastic.does-not-exist")
    _write_lead_meta(run_dir, "l-002", "real one")
    _write_query(run_dir, "l-002", 0, "elastic.auth-events")
    leads = lead_author.extract(run_dir)
    assert len(leads) == 2
    handoffs = lead_author.build_handoff(run_dir, leads)
    # Only the resolved lead survives.
    assert len(handoffs) == 1
    assert handoffs[0]["query_id"] == "elastic.auth-events"


def test_build_handoff_drops_ad_hoc_empty_query_id(run_dir: Path):
    _write_lead_meta(run_dir, "l-001", "ad-hoc")
    _write_query(run_dir, "l-001", 0, "")
    leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(run_dir, leads)
    assert handoffs == []


def test_build_handoff_co_dispatched_with_for_join(run_dir: Path, catalog: Path):
    """Cross-system join: each invocation lists its sibling template path."""
    _write_lead_meta(run_dir, "l-001", "cross-system")
    _write_query(run_dir, "l-001", 0, "elastic.auth-events")
    _write_query(run_dir, "l-001", 1, "host-state.process-list", {"pattern": "x"})
    leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(run_dir, leads)
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


def test_run_held_queue_lock_returns_zero(run_dir: Path, monkeypatch):
    # Pretend the queue lock is held by faking acquire_queue_lock.
    monkeypatch.setattr(lead_author, "acquire_queue_lock", lambda: None)
    monkeypatch.setattr(lead_author, "invoke_agent", _claude_should_not_be_called)
    assert lead_author.run(run_dir) == 0


def test_run_failure_marker_brakes_retry(run_dir: Path, monkeypatch):
    state = run_dir / "lead_author"
    state.mkdir()
    (state / "failure.txt").write_text("prior failure")
    monkeypatch.setattr(lead_author, "invoke_agent", _claude_should_not_be_called)
    # Stub the lock pair so we don't touch real fcntl state.
    monkeypatch.setattr(lead_author, "acquire_queue_lock", lambda: object())
    monkeypatch.setattr(lead_author, "release_queue_lock", lambda fh: None)
    monkeypatch.setattr(lead_author._author_shared, "acquire_repo_lock",
                        lambda timeout_seconds=None: object())
    monkeypatch.setattr(lead_author._author_shared, "release_repo_lock",
                        lambda fh: None)
    assert lead_author.run(run_dir) == 2


def test_run_done_sentinel_short_circuits(run_dir: Path, monkeypatch):
    state = run_dir / "lead_author"
    state.mkdir()
    (state / "done").write_text("ok")
    monkeypatch.setattr(lead_author, "invoke_agent", _claude_should_not_be_called)
    monkeypatch.setattr(lead_author, "acquire_queue_lock", lambda: object())
    monkeypatch.setattr(lead_author, "release_queue_lock", lambda fh: None)
    monkeypatch.setattr(lead_author._author_shared, "acquire_repo_lock",
                        lambda timeout_seconds=None: object())
    monkeypatch.setattr(lead_author._author_shared, "release_repo_lock",
                        lambda fh: None)
    assert lead_author.run(run_dir) == 0


# ---------------------------------------------------------------------------
# _parse_status_z
# ---------------------------------------------------------------------------


def test_parse_status_z_handles_spaces_and_rename():
    blob = " M file with spaces.txt\0?? new untracked\0R  dest-name\0src-name\0"
    records = lead_author._parse_status_z(blob)
    paths = {p for _, p in records}
    assert "file with spaces.txt" in paths
    assert "new untracked" in paths
    assert "dest-name" in paths
    assert "src-name" not in paths


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


def test_discover_system_drafts_finds_files_excluding_readme(tmp_path, monkeypatch):
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

    monkeypatch.setattr(lead_author, "SKILLS_DIR", skills)
    monkeypatch.setattr(lead_author, "REPO_ROOT", tmp_path)
    found = lead_author.discover_system_drafts()
    rel = [str(p.relative_to(tmp_path)) for p in found]
    assert rel == ["defender/skills/elastic/_draft/real-draft.md"]


def test_build_system_draft_handoffs_emits_triple(tmp_path, monkeypatch):
    skills = tmp_path / "defender" / "skills"
    (skills / "elastic" / "_draft").mkdir(parents=True)
    draft = skills / "elastic" / "_draft" / "falco-na.md"
    draft.write_text("---\nstatus: draft\n---\n")
    monkeypatch.setattr(lead_author, "REPO_ROOT", tmp_path)
    handoffs = lead_author.build_system_draft_handoffs([draft])
    assert handoffs == [{
        "draft_path": "defender/skills/elastic/_draft/falco-na.md",
        "system": "elastic",
        "skill_path": "defender/skills/elastic/SKILL.md",
    }]


def test_dirty_protected_paths_excludes_drafts():
    """Catalog drafts AND untracked system-skill drafts are expected queue content."""
    baseline = {
        ("??", "defender/skills/gather/queries/wazuh/_draft/newthing.md"),
        ("??", "defender/skills/elastic/_draft/falco-na.md"),
    }
    assert lead_author._dirty_protected_paths(baseline) == []


def test_dirty_protected_paths_catches_established_catalog_dirt():
    baseline = {
        ("??", "defender/skills/gather/queries/wazuh/_draft/ok.md"),
        (" M", "defender/skills/gather/queries/wazuh/auth-events.md"),
    }
    assert lead_author._dirty_protected_paths(baseline) == [
        "defender/skills/gather/queries/wazuh/auth-events.md"
    ]


def test_dirty_protected_paths_catches_dirty_skill_md():
    """A pre-existing dirty SKILL.md must trip preflight — lifts demand a clean target."""
    baseline = {
        ("??", "defender/skills/elastic/_draft/falco-na.md"),  # expected
        (" M", "defender/skills/elastic/SKILL.md"),            # not expected
    }
    assert lead_author._dirty_protected_paths(baseline) == [
        "defender/skills/elastic/SKILL.md"
    ]


# ---------------------------------------------------------------------------
# verify_postflight — git-history checks
# ---------------------------------------------------------------------------


def _run_git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd,
                          capture_output=True, text=True, check=True)


@pytest.fixture
def tmp_git_repo(tmp_path: Path, monkeypatch):
    """Stand up a tmp git repo with a catalog dir and point the driver at it."""
    repo = tmp_path / "repo"
    catalog = repo / "defender" / "skills" / "gather" / "queries"
    catalog.mkdir(parents=True)
    (catalog / ".gitkeep").write_text("")
    _run_git(repo, "init", "-q", "-b", "main")
    _run_git(repo, "config", "user.email", "test@example.com")
    _run_git(repo, "config", "user.name", "Test")
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "init")

    monkeypatch.setattr(lead_author, "REPO_ROOT", repo)
    return repo


def test_verify_postflight_rejects_amended_base(tmp_git_repo: Path):
    """`git commit --amend` rewrites the base commit; must be rejected."""
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    (tmp_git_repo / "defender" / "skills" / "gather" / "queries" / "x.md").write_text("x")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "--amend", "-m", "amended")

    ok, reason, _ = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "ancestor" in reason


def test_verify_postflight_accepts_clean_single_commit(tmp_git_repo: Path):
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    (tmp_git_repo / "defender" / "skills" / "gather" / "queries" / "x.md").write_text("x")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "add x")

    ok, reason, _ = lead_author.verify_postflight(base_sha, baseline)
    assert ok, f"expected ok, got reason={reason}"


def test_verify_postflight_rejects_reset_to_earlier(tmp_git_repo: Path):
    (tmp_git_repo / "defender" / "skills" / "gather" / "queries" / "a.md").write_text("a")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "add a")
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    _run_git(tmp_git_repo, "reset", "--hard", "-q", "HEAD~1")

    ok, reason, _ = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "ancestor" in reason


def test_verify_postflight_rejects_multi_commit(tmp_git_repo: Path):
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    for stem in ("a", "b"):
        (tmp_git_repo / "defender" / "skills" / "gather" / "queries" / f"{stem}.md").write_text(stem)
        _run_git(tmp_git_repo, "add", "-A")
        _run_git(tmp_git_repo, "commit", "-q", "-m", f"add {stem}")

    ok, reason, detail = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "more than one commit" in reason
    assert detail["rev_list_count"] == 2


def test_verify_postflight_rejects_commit_outside_scope(tmp_git_repo: Path):
    (tmp_git_repo / "defender" / "other").mkdir(parents=True)
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    (tmp_git_repo / "defender" / "other" / "stray.md").write_text("stray")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "stray edit")

    ok, reason, detail = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "outside lead_author scope" in reason
    assert "defender/other/stray.md" in detail["diff_paths"]


def test_verify_postflight_rejects_dirt_without_commit(tmp_git_repo: Path):
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    (tmp_git_repo / "defender" / "skills" / "gather" / "queries" / "uncommitted.md").write_text("u")

    ok, reason, detail = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "no commit" in reason
    assert "defender/skills/gather/queries/uncommitted.md" in detail["new_paths"]


def test_verify_postflight_rejects_sibling_dirt_alongside_commit(tmp_git_repo: Path):
    (tmp_git_repo / "defender" / "other").mkdir(parents=True)
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    (tmp_git_repo / "defender" / "skills" / "gather" / "queries" / "x.md").write_text("x")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "add x")
    (tmp_git_repo / "defender" / "other" / "leak.md").write_text("leak")

    ok, reason, detail = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "outside lead_author scope" in reason
    assert "defender/other/leak.md" in detail["new_paths"]


def test_verify_postflight_accepts_no_commit_clean(tmp_git_repo: Path):
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    ok, reason, detail = lead_author.verify_postflight(base_sha, baseline)
    assert ok, f"expected ok, got reason={reason}"
    assert detail["rev_list_count"] == 0


def test_verify_postflight_accepts_draft_promotion(tmp_git_repo: Path):
    """git mv {system}/_draft/foo.md → {system}/foo.md is allowed."""
    draft = tmp_git_repo / "defender" / "skills" / "gather" / "queries" / "wazuh" / "_draft"
    draft.mkdir(parents=True)
    (draft / "newthing.md").write_text("---\nid: wazuh.newthing\nstatus: draft\n---\n")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "seed draft")
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    # Promote: mv draft → root, then edit status.
    _run_git(tmp_git_repo, "mv",
             "defender/skills/gather/queries/wazuh/_draft/newthing.md",
             "defender/skills/gather/queries/wazuh/newthing.md")
    (tmp_git_repo / "defender" / "skills" / "gather" / "queries" / "wazuh" / "newthing.md").write_text(
        "---\nid: wazuh.newthing\nstatus: established\n---\n"
    )
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "promote")

    ok, reason, _ = lead_author.verify_postflight(base_sha, baseline)
    assert ok, f"expected ok, got reason={reason}"


def test_verify_postflight_accepts_draft_discard(tmp_git_repo: Path):
    """git rm of a draft is allowed."""
    draft = tmp_git_repo / "defender" / "skills" / "gather" / "queries" / "wazuh" / "_draft"
    draft.mkdir(parents=True)
    (draft / "throwaway.md").write_text("---\nid: wazuh.throwaway\nstatus: draft\n---\n")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "seed draft")
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    _run_git(tmp_git_repo, "rm", "-q",
             "defender/skills/gather/queries/wazuh/_draft/throwaway.md")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "discard")

    ok, reason, _ = lead_author.verify_postflight(base_sha, baseline)
    assert ok, f"expected ok, got reason={reason}"


def test_verify_postflight_rejects_established_deletion(tmp_git_repo: Path):
    """git rm of an established template is rejected."""
    catalog = tmp_git_repo / "defender" / "skills" / "gather" / "queries" / "wazuh"
    catalog.mkdir(parents=True, exist_ok=True)
    (catalog / "auth-events.md").write_text("---\nid: wazuh.auth-events\nstatus: established\n---\n")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "seed established")
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    _run_git(tmp_git_repo, "rm", "-q",
             "defender/skills/gather/queries/wazuh/auth-events.md")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "DESTROY")

    ok, reason, detail = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "established" in reason
    assert detail["deleted_path"].endswith("auth-events.md")


def test_verify_postflight_rejects_root_to_draft_demotion(tmp_git_repo: Path):
    """Renaming an established template into _draft/ is rejected."""
    catalog = tmp_git_repo / "defender" / "skills" / "gather" / "queries" / "wazuh"
    catalog.mkdir(parents=True, exist_ok=True)
    (catalog / "stable.md").write_text("---\nid: wazuh.stable\nstatus: established\n---\n")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "seed established")
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    (catalog / "_draft").mkdir(exist_ok=True)
    _run_git(tmp_git_repo, "mv",
             "defender/skills/gather/queries/wazuh/stable.md",
             "defender/skills/gather/queries/wazuh/_draft/stable.md")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "demote")

    ok, reason, _ = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "demote" in reason or "established" in reason


# ---------------------------------------------------------------------------
# System-skill lift postflight checks
# ---------------------------------------------------------------------------


def _seed_system_skill(repo: Path, system: str, draft_name: str) -> None:
    skill_dir = repo / "defender" / "skills" / system
    (skill_dir / "_draft").mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(f"---\nname: defender-{system}\n---\n# {system}\n")
    (skill_dir / "_draft" / "README.md").write_text("# surface declaration\n")
    (skill_dir / "_draft" / draft_name).write_text(
        f"---\nid: {system}.{draft_name[:-3]}\nstatus: draft\n---\n# pending\n"
    )
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", f"seed {system} system-skill + draft")


def test_verify_postflight_accepts_system_skill_lift(tmp_git_repo: Path):
    """Lift = Edit SKILL.md + git rm draft, committed together."""
    _seed_system_skill(tmp_git_repo, "elastic", "falco-na.md")
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    # Lift: append a section to SKILL.md, remove the draft.
    skill = tmp_git_repo / "defender" / "skills" / "elastic" / "SKILL.md"
    skill.write_text(skill.read_text() + "\n## Falco quirk\nworkaround text\n")
    _run_git(tmp_git_repo, "rm", "-q",
             "defender/skills/elastic/_draft/falco-na.md")
    _run_git(tmp_git_repo, "add", "defender/skills/elastic/SKILL.md")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "lift elastic.falco-na")

    ok, reason, _ = lead_author.verify_postflight(base_sha, baseline)
    assert ok, f"expected ok, got reason={reason}"


def test_verify_postflight_accepts_system_skill_discard(tmp_git_repo: Path):
    """Discard = git rm of a system-skill draft, no SKILL.md touch."""
    _seed_system_skill(tmp_git_repo, "elastic", "stale.md")
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    _run_git(tmp_git_repo, "rm", "-q",
             "defender/skills/elastic/_draft/stale.md")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "discard elastic.stale")

    ok, reason, _ = lead_author.verify_postflight(base_sha, baseline)
    assert ok, f"expected ok, got reason={reason}"


def test_verify_postflight_rejects_skill_md_deletion(tmp_git_repo: Path):
    """git rm of an established SKILL.md must fail."""
    _seed_system_skill(tmp_git_repo, "elastic", "x.md")
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    _run_git(tmp_git_repo, "rm", "-q", "defender/skills/elastic/SKILL.md")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "DESTROY SKILL")

    ok, reason, detail = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "established" in reason
    assert detail["deleted_path"].endswith("SKILL.md")


def test_verify_postflight_rejects_draft_readme_mutation(tmp_git_repo: Path):
    """_draft/README.md is a surface declaration — modifying it is rejected."""
    _seed_system_skill(tmp_git_repo, "elastic", "x.md")
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    readme = tmp_git_repo / "defender" / "skills" / "elastic" / "_draft" / "README.md"
    readme.write_text(readme.read_text() + "\nstomped\n")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "stomp README")

    ok, reason, detail = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "_draft/README.md" in reason or "surface declaration" in reason
    assert detail["touched_readme"].endswith("_draft/README.md")


def test_verify_postflight_rejects_skill_md_to_draft_demotion(tmp_git_repo: Path):
    """Renaming SKILL.md into _draft/ is rejected."""
    _seed_system_skill(tmp_git_repo, "elastic", "x.md")
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    _run_git(tmp_git_repo, "mv",
             "defender/skills/elastic/SKILL.md",
             "defender/skills/elastic/_draft/SKILL.md")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "demote SKILL.md")

    ok, reason, _ = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "demote" in reason or "established" in reason


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
    fake_executed = [object()]
    fake_handoff = [{
        "query_id": "fake.lead", "status": "established",
        "executed_template_path": "defender/skills/gather/queries/fake/lead.md",
        "neighbors": [], "invocations": [],
    }]
    monkeypatch.setattr(lead_author, "extract", lambda rd: fake_executed)
    monkeypatch.setattr(lead_author, "build_handoff", lambda rd, ex, jl=None: fake_handoff)
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5")
    monkeypatch.setattr(
        lead_author, "discover_system_drafts",
        lambda: [Path("/fake/a.md"), Path("/fake/b.md")],
    )
    handoffs, drafts, rc = lead_author._prepare_handoffs(run_dir, "BASE")
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
    monkeypatch.setattr(lead_author, "extract", lambda rd: [object()])
    monkeypatch.setattr(lead_author, "build_handoff", lambda rd, ex, jl=None: fake_handoff)
    # Seed two real draft files so build_system_draft_handoffs can compute
    # repo-relative paths.
    skills = tmp_path / "defender" / "skills"
    (skills / "elastic" / "_draft").mkdir(parents=True)
    drafts = [
        skills / "elastic" / "_draft" / "a.md",
        skills / "elastic" / "_draft" / "b.md",
    ]
    for d in drafts:
        d.write_text("---\nstatus: draft\n---\n")
    monkeypatch.setattr(lead_author, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(lead_author, "discover_system_drafts", lambda: drafts)
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "2")

    handoffs, pending, rc = lead_author._prepare_handoffs(run_dir, "BASE")
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
    monkeypatch.setattr(lead_author, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(lead_author, "discover_system_drafts", lambda: drafts)
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")

    handoffs, pending, rc = lead_author._prepare_handoffs(run_dir, "BASE")
    assert rc is None
    assert handoffs == []
    assert len(pending) == 2


def test_prepare_handoffs_both_empty_exits_zero(run_dir: Path, monkeypatch):
    """No executed leads AND no pending drafts → early exit 0, no work."""
    monkeypatch.setattr(lead_author, "discover_system_drafts", lambda: [])
    handoffs, pending, rc = lead_author._prepare_handoffs(run_dir, "BASE")
    assert rc == 0
    assert handoffs == []
    assert pending == []


def test_invoke_agent_includes_pending_drafts_in_prompt(
    run_dir: Path, monkeypatch
):
    """User prompt must carry the new pending_system_drafts section."""
    captured: dict = {}

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["input"] = kwargs.get("input", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(lead_author.subprocess, "run", _fake_run)
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
