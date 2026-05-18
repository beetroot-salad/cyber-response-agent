"""Lead-author driver — extraction shape, handoff shape, lock/sentinel paths.

Scope (minimal, per defender/CLAUDE.md): pin algorithmic invariants that
would silently drift (lead extraction, handoff JSON shape) plus the
gating logic that prevents the driver from spawning ``claude`` when it
shouldn't. We do NOT exhaustively mock ``claude`` — the post-flight
scope check is shell-and-git logic verifiable by reading the code.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
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


def _write_payload(run_dir: Path, position: int, suffix: str = "") -> Path:
    raw = run_dir / "gather_raw"
    raw.mkdir(exist_ok=True)
    p = raw / f"{position}{suffix}.json"
    p.write_text("{}")
    return p


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
    _write_payload(run_dir, 0)
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
    assert lead.query_id == "wazuh.auth-events"
    assert lead.params == {"host": "h1", "window": "1h"}
    assert lead.goal_text == "list auth events"
    assert lead.what_to_characterize == ("src_ip", "user")
    assert lead.cli == "wazuh_cli.py"


def test_extract_multi_query_fans_out(run_dir: Path):
    _write_payload(run_dir, 0)
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
    assert leads[1].query_index == 1
    assert leads[1].query_id == "wazuh.sudo-commands"


def test_extract_skips_entry_with_no_payload(run_dir: Path):
    # No payload written — entry must be silently skipped.
    _write_lead_sequence(run_dir, [
        {"position": 0, "lead_description": {"goal": "x"},
         "queries": [{"id": "wazuh.auth-events", "params": {}}]}
    ])
    assert lead_author.extract(run_dir) == []


def test_extract_result_refs_filter_multi_dot_sidecars(run_dir: Path):
    _write_payload(run_dir, 0)
    # 0.lead.json is a sidecar — must be excluded.
    (run_dir / "gather_raw" / "0.lead.json").write_text("{}")
    # 0a.json is a fan-out variant — must be included.
    _write_payload(run_dir, 0, suffix="a")
    _write_lead_sequence(run_dir, [
        {"position": 0, "lead_description": {"goal": "x"},
         "queries": [{"id": "wazuh.auth-events", "params": {}}]}
    ])
    leads = lead_author.extract(run_dir)
    assert len(leads) == 1
    names = sorted(p.name for p in leads[0].result_refs)
    assert names == ["0.json", "0a.json"]


def test_extract_ad_hoc_query_has_none_cli(run_dir: Path):
    _write_payload(run_dir, 0)
    _write_lead_sequence(run_dir, [
        {"position": 0, "lead_description": {"goal": "ad-hoc"},
         "queries": [{"id": "", "params": {}}]}
    ])
    leads = lead_author.extract(run_dir)
    assert leads[0].cli is None


# ---------------------------------------------------------------------------
# build_handoff()
# ---------------------------------------------------------------------------


def test_build_handoff_mode_a_populates_executed_template_path(run_dir: Path):
    _write_payload(run_dir, 0)
    _write_lead_sequence(run_dir, [
        {"position": 0, "lead_description": {"goal": "list auth events"},
         "queries": [{"id": "wazuh.auth-events", "params": {}}]}
    ])
    leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(run_dir, leads)
    assert len(handoffs) == 1
    h = handoffs[0]
    assert h["mode"] == "A"
    assert h["system"] == "wazuh"
    assert h["executed_template_path"] is not None
    assert h["executed_template_path"].endswith("wazuh/auth-events.md")
    assert isinstance(h["neighbors"], list)
    assert len(h["neighbors"]) <= 3
    # JSON-serializable so the prompt builder won't choke.
    json.dumps(h)


def test_build_handoff_mode_b_executed_template_path_null(run_dir: Path):
    _write_payload(run_dir, 0)
    _write_lead_sequence(run_dir, [
        {"position": 0, "lead_description": {"goal": "novel intent"},
         "queries": [{"id": "wazuh.does-not-exist", "params": {}}]}
    ])
    leads = lead_author.extract(run_dir)
    handoffs = lead_author.build_handoff(run_dir, leads)
    h = handoffs[0]
    assert h["mode"] == "B"
    assert h["executed_template_path"] is None
    # system inferred from prefix when it's a known cli registry entry.
    assert h["system"] == "wazuh"


def test_build_handoff_ad_hoc_has_null_system(run_dir: Path):
    _write_payload(run_dir, 0)
    _write_lead_sequence(run_dir, [
        {"position": 0, "lead_description": {"goal": "ad-hoc"},
         "queries": [{"id": "", "params": {}}]}
    ])
    leads = lead_author.extract(run_dir)
    h = lead_author.build_handoff(run_dir, leads)[0]
    assert h["mode"] == "B"
    assert h["system"] is None


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
    # Construct a porcelain-v1 -z blob by hand. Format: ``XY <space> path``
    # where XY is exactly 2 chars. With -z, records are NUL-separated.
    # Rename/copy uses TWO records: destination first, then source.
    #
    # Cases:
    #   - " M file with spaces.txt"     — modified, working tree
    #   - "?? new untracked"            — untracked
    #   - "R  dest-name" + "src-name"   — rename, destination first
    blob = " M file with spaces.txt\0?? new untracked\0R  dest-name\0src-name\0"
    records = lead_author._parse_status_z(blob)
    paths = {p for _, p in records}
    assert "file with spaces.txt" in paths
    assert "new untracked" in paths
    # Rename: we key on the destination, the source record is consumed.
    assert "dest-name" in paths
    assert "src-name" not in paths


# ---------------------------------------------------------------------------
# verify_postflight — amend / rewrite detection
# ---------------------------------------------------------------------------


def _run_git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd,
                          capture_output=True, text=True, check=True)


@pytest.fixture
def tmp_git_repo(tmp_path: Path, monkeypatch):
    """Stand up a tmp git repo with a catalog dir and point the driver at it."""
    repo = tmp_path / "repo"
    (repo / "defender" / "skills" / "gather" / "queries").mkdir(parents=True)
    (repo / "defender" / "skills" / "gather" / "queries" / ".gitkeep").write_text("")
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
    # Agent runs `git commit --amend` on the base commit, rewriting history.
    (tmp_git_repo / "defender" / "skills" / "gather" / "queries" / "x.md").write_text("x")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "--amend", "-m", "amended")

    ok, reason, _ = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "ancestor" in reason


def test_verify_postflight_accepts_clean_single_commit(tmp_git_repo: Path):
    """Normal happy path: one catalog-only commit on top of base."""
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    (tmp_git_repo / "defender" / "skills" / "gather" / "queries" / "x.md").write_text("x")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "add x")

    ok, reason, _ = lead_author.verify_postflight(base_sha, baseline)
    assert ok, f"expected ok, got reason={reason}"


def test_verify_postflight_rejects_reset_to_earlier(tmp_git_repo: Path):
    """`git reset --hard <earlier>` makes base_sha not-an-ancestor; reject."""
    # Add an extra commit first so we have somewhere to reset to.
    (tmp_git_repo / "defender" / "skills" / "gather" / "queries" / "a.md").write_text("a")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "add a")
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    # Agent resets HEAD back past base_sha.
    _run_git(tmp_git_repo, "reset", "--hard", "-q", "HEAD~1")

    ok, reason, _ = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "ancestor" in reason


def test_verify_postflight_rejects_multi_commit(tmp_git_repo: Path):
    """Two commits since base is a hard-rule violation (one commit per tick)."""
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
    """Single commit that touches a path outside the catalog must be rejected."""
    (tmp_git_repo / "defender" / "other").mkdir(parents=True)
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    # Agent commits a file outside the catalog.
    (tmp_git_repo / "defender" / "other" / "stray.md").write_text("stray")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "stray edit")

    ok, reason, detail = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "outside catalog" in reason
    assert "defender/other/stray.md" in detail["diff_paths"]


def test_verify_postflight_rejects_dirt_without_commit(tmp_git_repo: Path):
    """No commit but new dirty/untracked records ⇒ violation (agent edited and bailed)."""
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    # Agent wrote a file but never committed.
    (tmp_git_repo / "defender" / "skills" / "gather" / "queries" / "uncommitted.md").write_text("u")

    ok, reason, detail = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "no commit" in reason
    assert "defender/skills/gather/queries/uncommitted.md" in detail["new_paths"]


def test_verify_postflight_rejects_sibling_dirt_alongside_commit(tmp_git_repo: Path):
    """Commit landed cleanly but agent also left dirt under defender/ outside catalog."""
    (tmp_git_repo / "defender" / "other").mkdir(parents=True)
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    # Clean catalog commit…
    (tmp_git_repo / "defender" / "skills" / "gather" / "queries" / "x.md").write_text("x")
    _run_git(tmp_git_repo, "add", "-A")
    _run_git(tmp_git_repo, "commit", "-q", "-m", "add x")
    # …plus an uncommitted edit in a sibling defender/ path.
    (tmp_git_repo / "defender" / "other" / "leak.md").write_text("leak")

    ok, reason, detail = lead_author.verify_postflight(base_sha, baseline)
    assert not ok
    assert "outside catalog" in reason
    assert "defender/other/leak.md" in detail["new_paths"]


def test_verify_postflight_accepts_no_commit_clean(tmp_git_repo: Path):
    """Agent decided every handoff was skip ⇒ no commit, no dirt, exit 0."""
    base_sha = lead_author._git_head()
    baseline = lead_author._git_status_records()
    # No edits.
    ok, reason, detail = lead_author.verify_postflight(base_sha, baseline)
    assert ok, f"expected ok, got reason={reason}"
    assert detail["rev_list_count"] == 0
