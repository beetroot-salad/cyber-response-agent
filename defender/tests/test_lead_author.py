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
import yaml

import lead_author  # type: ignore[import-not-found]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _write_lead_sequence(run_dir: Path, entries: list[dict]) -> None:
    (run_dir / "lead_sequence.yaml").write_text(
        yaml.safe_dump({"case_id": "test", "alert_ref": "alert.json", "entries": entries})
    )


def _write_invocation(
    run_dir: Path,
    position: int,
    *,
    query_index: int = 0,
    is_multi: bool = False,
    payload: str = "{}",
    payload_status: str = "ok",
    payload_digest: str = "ok digest",
) -> Path:
    """Write the canonical payload + observation sidecar for one invocation."""
    raw = run_dir / "gather_raw"
    raw.mkdir(exist_ok=True)
    suffix = chr(ord("a") + query_index) if is_multi else ""
    payload_path = raw / f"{position}{suffix}.json"
    payload_path.write_text(payload)
    sidecar = raw / f"{position}{suffix}.observations.json"
    sidecar.write_text(json.dumps({
        "payload_status": payload_status,
        "payload_digest": payload_digest,
    }))
    return payload_path


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    rd = tmp_path / "test-run-001"
    rd.mkdir()
    (rd / "gather_raw").mkdir()
    return rd


# ---------------------------------------------------------------------------
# extract()
# ---------------------------------------------------------------------------


def test_extract_single_query_per_entry(run_dir: Path):
    _write_invocation(run_dir, 0)
    _write_lead_sequence(run_dir, [
        {
            "position": 0,
            "lead_description": {"goal": "list auth events",
                                 "what_to_characterize": ["src_ip", "user"]},
            "queries": [
                {"id": "wazuh.auth-events", "params": {"host": "h1", "window": "1h"}}
            ],
        }
    ])
    leads = lead_author.extract(run_dir)
    assert len(leads) == 1
    lead = leads[0]
    assert lead.position == 0
    assert lead.query_index == 0
    assert lead.is_multi_query is False
    assert lead.query_id == "wazuh.auth-events"
    assert lead.params == {"host": "h1", "window": "1h"}
    assert lead.goal_text == "list auth events"
    assert lead.what_to_characterize == ("src_ip", "user")
    assert lead.result_ref.name == "0.json"
    assert lead.sidecar_path.name == "0.observations.json"


def test_extract_multi_query_fans_out(run_dir: Path):
    _write_invocation(run_dir, 0, query_index=0, is_multi=True)
    _write_invocation(run_dir, 0, query_index=1, is_multi=True)
    _write_lead_sequence(run_dir, [
        {
            "position": 0,
            "lead_description": {"goal": "fan out"},
            "queries": [
                {"id": "wazuh.auth-events", "params": {}},
                {"id": "wazuh.sudo-commands", "params": {}},
            ],
        }
    ])
    leads = lead_author.extract(run_dir)
    assert len(leads) == 2
    assert leads[0].query_index == 0
    assert leads[0].is_multi_query is True
    assert leads[0].result_ref.name == "0a.json"
    assert leads[1].query_index == 1
    assert leads[1].query_id == "wazuh.sudo-commands"
    assert leads[1].result_ref.name == "0b.json"


def test_extract_skips_entry_with_no_payload(run_dir: Path):
    # No payload written — entry must be silently skipped.
    _write_lead_sequence(run_dir, [
        {"position": 0, "lead_description": {"goal": "x"},
         "queries": [{"id": "wazuh.auth-events", "params": {}}]}
    ])
    assert lead_author.extract(run_dir) == []


def test_extract_multi_query_skips_missing_invocation(run_dir: Path):
    # Multi-query with only first payload present — second skipped.
    _write_invocation(run_dir, 0, query_index=0, is_multi=True)
    # No 0b.json written.
    _write_lead_sequence(run_dir, [
        {
            "position": 0,
            "lead_description": {"goal": "partial fan-out"},
            "queries": [
                {"id": "wazuh.auth-events", "params": {}},
                {"id": "wazuh.sudo-commands", "params": {}},
            ],
        }
    ])
    leads = lead_author.extract(run_dir)
    assert len(leads) == 1
    assert leads[0].query_id == "wazuh.auth-events"


# ---------------------------------------------------------------------------
# build_handoff()
# ---------------------------------------------------------------------------


def test_build_handoff_groups_by_template(run_dir: Path):
    """Same template invoked 3× → one handoff with 3 invocations."""
    for i in range(3):
        _write_invocation(run_dir, i, payload_digest=f"call-{i}")
    _write_lead_sequence(run_dir, [
        {
            "position": i,
            "lead_description": {"goal": f"call {i}"},
            "queries": [{"id": "wazuh.auth-events", "params": {"host": f"h{i}"}}],
        }
        for i in range(3)
    ])
    leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(run_dir, leads)
    assert len(handoffs) == 1
    h = handoffs[0]
    assert h["query_id"] == "wazuh.auth-events"
    assert h["status"] == "established"
    assert h["executed_template_path"].endswith("wazuh/auth-events.md")
    assert len(h["invocations"]) == 3
    assert [inv["payload_digest"] for inv in h["invocations"]] == [
        "call-0", "call-1", "call-2",
    ]
    # JSON-serializable so the prompt builder won't choke.
    json.dumps(h)


def test_build_handoff_includes_rendered_query_and_sidecar(run_dir: Path):
    _write_invocation(
        run_dir, 0,
        payload_status="suspect_empty",
        payload_digest="0 events; data.srcip is IP-typed",
    )
    _write_lead_sequence(run_dir, [
        {"position": 0, "lead_description": {"goal": "x"},
         "queries": [{"id": "wazuh.auth-events",
                      "params": {"host": "bastion-01", "window": "1h"}}]}
    ])
    leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(run_dir, leads)
    assert len(handoffs) == 1
    inv = handoffs[0]["invocations"][0]
    assert inv["payload_status"] == "suspect_empty"
    assert "data.srcip" in inv["payload_digest"]
    # rendered_query should contain the substituted params from the
    # ## Query body — wazuh.auth-events references ${window}; unbound
    # placeholders like ${host_clause} pass through verbatim so the
    # leak is visible.
    assert inv["rendered_query"]  # non-empty
    assert "--window 1h" in inv["rendered_query"]
    assert "${host_clause}" in inv["rendered_query"]


def test_build_handoff_missing_sidecar_raises(run_dir: Path):
    """Missing observation sidecar is a gather-regression — fail loud."""
    raw = run_dir / "gather_raw"
    raw.mkdir(exist_ok=True)
    (raw / "0.json").write_text("{}")
    # No 0.observations.json written.
    _write_lead_sequence(run_dir, [
        {"position": 0, "lead_description": {"goal": "x"},
         "queries": [{"id": "wazuh.auth-events", "params": {}}]}
    ])
    leads = lead_author.extract(run_dir)
    with pytest.raises(lead_author.LeadAuthorError, match="observation sidecar"):
        lead_author.build_handoff(run_dir, leads)


def test_build_handoff_invalid_payload_status_raises(run_dir: Path):
    raw = run_dir / "gather_raw"
    raw.mkdir(exist_ok=True)
    (raw / "0.json").write_text("{}")
    (raw / "0.observations.json").write_text(json.dumps({
        "payload_status": "weird",
        "payload_digest": "x",
    }))
    _write_lead_sequence(run_dir, [
        {"position": 0, "lead_description": {"goal": "x"},
         "queries": [{"id": "wazuh.auth-events", "params": {}}]}
    ])
    leads = lead_author.extract(run_dir)
    with pytest.raises(lead_author.LeadAuthorError, match="payload_status"):
        lead_author.build_handoff(run_dir, leads)


def test_build_handoff_drops_unresolved_query_id(run_dir: Path):
    """Unresolved query_id ⇒ skip with a corpus-health warning, don't crash."""
    _write_invocation(run_dir, 0)
    _write_invocation(run_dir, 1)
    _write_lead_sequence(run_dir, [
        {"position": 0, "lead_description": {"goal": "novel"},
         "queries": [{"id": "wazuh.does-not-exist", "params": {}}]},
        {"position": 1, "lead_description": {"goal": "real one"},
         "queries": [{"id": "wazuh.auth-events", "params": {}}]},
    ])
    leads = lead_author.extract(run_dir)
    assert len(leads) == 2
    handoffs = lead_author.build_handoff(run_dir, leads)
    # Only the resolved lead survives.
    assert len(handoffs) == 1
    assert handoffs[0]["query_id"] == "wazuh.auth-events"


def test_build_handoff_drops_ad_hoc_empty_query_id(run_dir: Path):
    _write_invocation(run_dir, 0)
    _write_lead_sequence(run_dir, [
        {"position": 0, "lead_description": {"goal": "ad-hoc"},
         "queries": [{"id": "", "params": {}}]}
    ])
    leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(run_dir, leads)
    assert handoffs == []


def test_build_handoff_co_dispatched_with_for_join(run_dir: Path):
    """Cross-system join: each invocation lists its sibling template path."""
    _write_invocation(run_dir, 0, query_index=0, is_multi=True)
    _write_invocation(run_dir, 0, query_index=1, is_multi=True)
    _write_lead_sequence(run_dir, [
        {
            "position": 0,
            "lead_description": {"goal": "cross-system"},
            "queries": [
                {"id": "wazuh.auth-events", "params": {}},
                {"id": "host-query.process-list", "params": {"pattern": "x"}},
            ],
        }
    ])
    leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(run_dir, leads)
    # Two handoffs (one per template).
    assert len(handoffs) == 2
    by_id = {h["query_id"]: h for h in handoffs}
    auth_inv = by_id["wazuh.auth-events"]["invocations"][0]
    assert auth_inv["composite_kind"] == "join"
    assert any("host-query/process-list.md" in p for p in auth_inv["co_dispatched_with"])


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


def test_verify_postflight_rejects_commit_outside_catalog(tmp_git_repo: Path):
    (tmp_git_repo / "defender" / "other").mkdir(parents=True)
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    (tmp_git_repo / "defender" / "other" / "stray.md").write_text("stray")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "stray edit")

    ok, reason, detail = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "outside catalog" in reason
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
    assert "outside catalog" in reason
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
