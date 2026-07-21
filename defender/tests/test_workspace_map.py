"""Tests for scripts/workspace_map.py — the on-disk orientation baked
into the agent's message 0 by run.py:build_prompt.

The load-bearing guard here is `test_no_credential_signal`: the map must
never surface adapter credentials / `.env` paths / env-var status to the
orchestrator. Doing so is the regression that issue #255 fixed in the v2
tree — the orchestrator was handed a `.env` it could neither read nor
own and burned ~1.1k thinking tokens thrashing on it. Credential sourcing
is each adapter's job at call time (gather subagent), so the
orchestrator-facing map must stay credential-free.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_WM_PATH = Path(__file__).resolve().parents[1] / "scripts" / "workspace_map.py"
_spec = importlib.util.spec_from_file_location("workspace_map", _WM_PATH)
wm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wm)


def test_canonical_sections_present(tmp_path: Path):
    out = wm.workspace_map(tmp_path)
    for header in (
        "# Workspace map",
        "## Absolute roots",
        "## Run dir",
        "## System skills",
        "## Adapters",
        "## Gather query templates",
    ):
        assert header in out, f"missing section: {header}"


def test_no_credential_signal(tmp_path: Path):
    """#255 guard: the orchestrator-facing map must carry no credential
    or env-var signal — no `.env` path, no MISSING/SET status, no secret
    var names. The run-dir path is masked first so a tmp dir named after
    this test can't inject a token."""
    out = wm.workspace_map(tmp_path).replace(str(tmp_path), "RUNDIR").lower()
    for token in (".env", "missing", "elastic_password", "elasticsearch_url",
                  "password", "credential", "watched_env", "source it"):
        assert token not in out, f"credential signal leaked into map: {token!r}"


def test_run_dir_contents_listed(tmp_path: Path):
    (tmp_path / "alert.json").write_text("{}")
    out = wm.workspace_map(tmp_path)
    assert "alert.json" in out


def test_gather_raw_suppressed(tmp_path: Path):
    """#264 cleanse: `gather_raw/` is a subagent-only artifact (raw query
    payloads + the leads table). The orchestrator reasons from gather's
    returned summary, never the raw tree, so the map must not name it — not
    the dir entry, not its contents — even when it exists and is populated."""
    (tmp_path / "alert.json").write_text("{}")
    gr = tmp_path / "gather_raw"
    gr.mkdir()
    (gr / "l-001.lead.json").write_text("{}")
    out = wm.workspace_map(tmp_path).replace(str(tmp_path), "RUNDIR")
    assert "alert.json" in out
    assert "gather_raw" not in out


def test_output_ends_with_newline(tmp_path: Path):
    assert wm.workspace_map(tmp_path).endswith("\n")
