"""Tests for run's first-party API-key provisioning (the .env-leak fix).

The PydanticAI engine bills the first-party REST API, so it must source a real
key from `.env` rather than the ambient ANTHROPIC_API_KEY (which, inside a Claude
Code session, is the subscription credential and 401s). Pins: a `.env` key wins
over the ambient value, `$DEFENDER_ENV_FILE` overrides, and absence is reported.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

_DEFENDER = Path(__file__).resolve().parents[1]
if str(_DEFENDER) not in sys.path:
    sys.path.insert(0, str(_DEFENDER))

import run  # noqa: E402


def test_read_env_key_parses_quotes_and_export(tmp_path):
    f = tmp_path / ".env"
    f.write_text('# comment\nexport ANTHROPIC_API_KEY="sk-ant-api03-abc"\nOTHER=1\n')
    assert run._read_env_key(f) == "sk-ant-api03-abc"


def test_read_env_key_absent_returns_none(tmp_path):
    f = tmp_path / ".env"
    f.write_text("ELASTIC_PASSWORD=hunter2\n")
    assert run._read_env_key(f) is None


def test_explicit_env_file_wins(tmp_path, monkeypatch):
    explicit = tmp_path / "custom.env"
    explicit.write_text("ANTHROPIC_API_KEY=sk-ant-api03-explicit\n")
    monkeypatch.setenv("DEFENDER_ENV_FILE", str(explicit))
    key, src = run.resolve_first_party_key()
    assert key == "sk-ant-api03-explicit"
    assert src == explicit


def test_repo_root_env_used_when_no_explicit(tmp_path, monkeypatch):
    monkeypatch.delenv("DEFENDER_ENV_FILE", raising=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("ANTHROPIC_API_KEY=sk-ant-api03-repo\n")
    key, src = run.resolve_first_party_key(root=repo)
    assert key == "sk-ant-api03-repo"
    assert src == repo / ".env"


def test_resolver_returns_none_when_all_candidates_missing(tmp_path, monkeypatch):
    monkeypatch.delenv("DEFENDER_ENV_FILE", raising=False)
    missing = tmp_path / "repo"
    key, src = run.resolve_first_party_key(root=missing, main_repo_root=missing)
    assert key is None
    assert src is None
