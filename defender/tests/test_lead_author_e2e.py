"""End-to-end ``lead_author.run`` exercise with a mocked agent."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from defender.learning import lead_author


def _setup(tmp_repo, monkeypatch, tmp_path) -> tuple[Path, Path]:
    """Seed catalog + a sample run dir; rebind module globals."""
    repo = tmp_repo.root
    catalog = repo / "defender" / "skills" / "gather" / "queries" / "wazuh"
    catalog.mkdir(parents=True)
    (catalog / "auth-events.md").write_text(
        "---\nid: wazuh.auth-events\n---\n\n"
        "## Goal\n\ng\n\n"
        "## What to characterize\n\n- x\n\n"
        "## Query\n\n```bash\necho ${window} ${run_dir}\n```\n\n"
        "## Common pitfalls\n\n- none\n"
    )
    (catalog / "sudo-commands.md").write_text(
        "---\nid: wazuh.sudo-commands\n---\n\n"
        "## Goal\n\ng\n\n"
        "## What to characterize\n\n- x\n\n"
        "## Query\n\n```bash\necho ${window} ${run_dir}\n```\n\n"
        "## Common pitfalls\n\n- none\n"
    )
    tmp_repo.run_git("add", "-A")
    tmp_repo.run_git("commit", "-q", "-m", "seed catalog")

    run = tmp_path / "20260515T000000Z-case"
    run.mkdir()
    (run / "lead_sequence.yaml").write_text(
        yaml.safe_dump(
            {
                "case_id": run.name,
                "alert_ref": "alert.json",
                "entries": [
                    {
                        "position": 0,
                        "lead_description": {
                            "goal": "characterize auth events on host h1",
                            "what_to_characterize": ["source ip diversity"],
                        },
                        "queries": [
                            {"id": "wazuh.auth-events", "params": {"host": "h1"}}
                        ],
                        "result_ref": "gather_raw/0.json",
                    }
                ],
            }
        )
    )
    (run / "gather_raw").mkdir()
    (run / "gather_raw" / "0.json").write_text("{}")

    learning = repo / "defender" / "learning"
    cat_root = catalog.parent
    pending = learning / "_pending_leads"
    monkeypatch.setattr(lead_author, "REPO_ROOT", repo)
    monkeypatch.setattr(lead_author, "LEARNING_DIR", learning)
    monkeypatch.setattr(lead_author, "CATALOG_DIR", cat_root)
    monkeypatch.setattr(lead_author, "PENDING_DIR", pending)
    monkeypatch.setattr(lead_author, "LOCK_FILE", pending / ".lock")
    # The neighbors module's CATALOG_ROOT is at workspace-level — rebind
    # via lead_author's bound reference so we patch the same module object
    # the driver actually uses. (``from defender.learning import
    # lead_neighbors`` here would resolve to a different module object
    # post-tmp_repo purge.)
    monkeypatch.setattr(lead_author.lead_neighbors, "CATALOG_ROOT", cat_root)

    return repo, run


def test_run_no_op_path(tmp_repo, monkeypatch, tmp_path):
    """Agent decides nothing needs editing — driver records a clean no-op."""
    repo, run_dir = _setup(tmp_repo, monkeypatch, tmp_path)

    def fake_invoke(run_dir_arg, handoffs, *, log_path=None):
        assert run_dir_arg == run_dir
        # One handoff because we seeded one entry.
        assert len(handoffs) == 1
        h = handoffs[0]
        assert h["query_id"] == "wazuh.auth-events"
        assert h["mode"] == "A"
        assert h["executed_template_path"].endswith("auth-events.md")
        return {
            "commit_sha": None,
            "actions": [],
            "tier1_verdict": "not_run",
            "executed_leads": [
                {
                    "position": 0,
                    "query_index": 0,
                    "query_id": "wazuh.auth-events",
                }
            ],
        }

    monkeypatch.setattr(lead_author, "invoke_agent", fake_invoke)
    rc = lead_author.run(run_dir)
    assert rc == 0

    # Result file + done sentinel were written.
    result = json.loads((run_dir / "lead_author" / "result.json").read_text())
    assert result["commit_sha"] is None
    assert result["actions"] == []
    assert (run_dir / "lead_author" / "done").is_file()
    # Re-invocation is a refuse — sentinel blocks.
    rc2 = lead_author.run(run_dir)
    assert rc2 == 2


def test_run_commit_path(tmp_repo, monkeypatch, tmp_path):
    """Agent edits + commits — driver verifies the HEAD invariants."""
    repo, run_dir = _setup(tmp_repo, monkeypatch, tmp_path)

    def fake_invoke(run_dir_arg, handoffs, *, log_path=None):
        # Simulate the agent doing an edit + commit.
        catalog = (
            repo / "defender" / "skills" / "gather" / "queries" / "wazuh"
        )
        tpl = catalog / "auth-events.md"
        tpl.write_text(tpl.read_text() + "\nlearned-pattern: x\n")
        tmp_repo.run_git("add", "-A")
        tmp_repo.run_git("commit", "-q", "-m", "fold case")
        sha = tmp_repo.run_git("rev-parse", "HEAD").stdout.strip()
        return {
            "commit_sha": sha,
            "actions": [
                {
                    "kind": "fold",
                    "template_id": "wazuh.auth-events",
                    "neighbors_considered": ["wazuh.sudo-commands"],
                    "mode": "A",
                    "rationale": "fold the new pattern in",
                }
            ],
            "tier1_verdict": "pass",
            "executed_leads": [
                {
                    "position": 0,
                    "query_index": 0,
                    "query_id": "wazuh.auth-events",
                }
            ],
        }

    monkeypatch.setattr(lead_author, "invoke_agent", fake_invoke)
    rc = lead_author.run(run_dir)
    assert rc == 0

    result = json.loads((run_dir / "lead_author" / "result.json").read_text())
    assert result["commit_sha"] is not None
    assert len(result["actions"]) == 1
    assert result["tier1_verdict"] == "pass"
