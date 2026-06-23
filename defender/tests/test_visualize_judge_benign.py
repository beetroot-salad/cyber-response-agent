"""Tests for benign (FP-direction) rendering in the judge transcript.

The transcript historically rendered only the adversarial direction
(``actor_story.md`` / ``judge_findings.yaml``). The benign direction
persists under ``*_benign`` names; these tests cover that the benign
sections render when those artifacts exist and stay absent otherwise.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts" / "visualize"
# visualize_judge imports siblings via the `defender.scripts.visualize.*`
# namespace, resolved by the repo root on sys.path (pytest pythonpath); keep
# the package dir importable too for the by-path module loads below.
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vj = _load("visualize_judge")
vp = _load("visualize_primitives")

_BENIGN_JUDGE = {
    "outcome": "survived-fp",
    "outcome_rationale": "escalated an authorized monitoring probe",
    "confidence": "high",
    "encounter_analysis": "routine sweep would have been flagged as recon",
    "defender_findings": [
        {
            "type": "missing-knowledge",
            "subject_anchor": "svc.monitoring",
            "subject_topic": "service-account authorization",
            "finding": "lacked the standing fact about svc.monitoring sweeps",
            "citations": [],
        }
    ],
    "environment_observations": [
        {
            "alert_rule_ids": ["v2-falco-suspicious-network-tool"],
            "relevance_criteria": "web-tier host running nc -z toward a trust peer",
            "fact": "svc.monitoring performs scheduled nc -z reachability probes",
            "entities": [{"type": "identity", "class": "service-account"}],
        }
    ],
}


def test_benign_section_empty_when_no_judge():
    assert vj.render_judge_benign_section(None) == ""


def test_benign_section_renders_outcome_findings_and_env_obs():
    html = vj.render_judge_benign_section(_BENIGN_JUDGE)
    assert 'id="sec-judge-benign-outcome"' in html
    assert "out-survived-fp" in html
    # benign findings use a distinct anchor prefix so they never collide with
    # adversarial finding ids on an inconclusive run that rendered both.
    assert 'id="benign-finding-0"' in html
    assert 'id="sec-judge-benign-env"' in html
    assert "svc.monitoring performs scheduled nc -z reachability probes" in html
    assert "v2-falco-suspicious-network-tool" in html
    assert "identity/service-account" in html


def test_env_observation_card_handles_missing_entities():
    html = vj.render_env_observation(0, {
        "alert_rule_ids": ["r1"],
        "relevance_criteria": "c",
        "fact": "f",
    })
    assert 'id="env-obs-0"' in html
    assert "env-obs-ents" not in html  # no entities block when absent


def test_actor_benign_section_empty_when_story_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path))
    assert vj.render_judge_actor_benign_section("nope") == ""


def test_actor_benign_section_renders_story(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path))
    learn = tmp_path / "runs" / "case-1"
    learn.mkdir(parents=True)
    (learn / "actor_benign_story.md").write_text("routine sweep story")
    html = vj.render_judge_actor_benign_section("case-1")
    assert 'id="sec-actor-benign"' in html
    assert "routine sweep story" in html


def test_oracle_benign_section_empty_when_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path))
    assert vj.render_judge_oracle_benign_section("nope") == ""


def test_toc_omits_benign_block_by_default():
    toc = vj.render_judge_toc(2)
    assert "sec-actor-benign" not in toc
    assert "§ Actor (benign)" not in toc


def test_toc_includes_benign_block_when_requested():
    toc = vj.render_judge_toc(2, n_benign_findings=1)
    assert "sec-actor-benign" in toc
    assert 'href="#benign-finding-0"' in toc
    assert "sec-judge-benign-env" in toc


def test_learning_run_dir_honors_state_dir(tmp_path, monkeypatch):
    # Out-of-repo concurrent mode (the off-process learn worker's reason to exist):
    # the LEARN stage persists judge artifacts under $DEFENDER_LEARNING_STATE_DIR,
    # so the (re-)render must resolve them there — not the in-repo learning/runs path.
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    assert vp._learning_run_dir("case-9") == (tmp_path / "state").resolve() / "runs" / "case-9"


def test_learning_run_dir_defaults_in_repo(monkeypatch):
    monkeypatch.delenv("DEFENDER_LEARNING_STATE_DIR", raising=False)
    assert vp._learning_run_dir("case-9") == vp.REPO_ROOT / "defender" / "learning" / "runs" / "case-9"


def test_adversarial_finding_anchor_unchanged():
    # The default anchor prefix must stay `finding-` so the adversarial TOC
    # links (#finding-N) keep resolving.
    html = vj.render_judge_finding(0, {
        "type": "missing-knowledge",
        "subject_anchor": "a",
        "subject_topic": "t",
        "finding": "f",
        "citations": [],
    })
    assert 'id="finding-0"' in html
