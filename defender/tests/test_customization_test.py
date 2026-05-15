"""Unit tests for the customization runner.

Covers:
  * section splitter (definition vs. template)
  * rubric scoring (expected + forbidden substrings)
  * trial aggregation (2/3 rule)
  * end-to-end run_file behaviour with a mocked invoker
"""
from __future__ import annotations

from pathlib import Path

import yaml

from defender.learning import customization_test as ct
from defender.learning._agent_stream import AgentStreamError


TEMPLATE = """---
id: wazuh.example
---

## Goal

g

## What to characterize

- one
- two

## Query

```bash
python3 defender/scripts/tools/wazuh_cli.py query --query 'rule.id:5710'
```

`${rule_id}` is documented here.

## Filter binding

- `rule_id` → the numeric Wazuh rule id.

## Common pitfalls

- nothing

## Baseline

- nothing
"""


def test_split_template_separates_intent_from_example():
    defn, tpl = ct.split_template(TEMPLATE)
    # Definition holds intent surface only.
    assert "## Goal" in defn
    assert "## What to characterize" in defn
    assert "## Common pitfalls" in defn
    assert "## Baseline" in defn
    assert "## Query" not in defn
    assert "## Filter binding" not in defn
    # Template holds the example.
    assert "## Query" in tpl
    assert "## Filter binding" in tpl
    assert "## Goal" not in tpl


def test_split_template_strips_frontmatter():
    defn, tpl = ct.split_template(TEMPLATE)
    assert "id: wazuh.example" not in defn
    assert "id: wazuh.example" not in tpl


def test_score_output_pass_when_expected_present():
    ok, detail = ct.score_output(
        "stdout has rule.id:5710 in it",
        {"expected_substrings": ["rule.id:5710"], "forbidden_substrings": []},
    )
    assert ok
    assert detail["missing_expected"] == []
    assert detail["present_forbidden"] == []


def test_score_output_fail_when_expected_missing():
    ok, detail = ct.score_output(
        "stdout has nothing useful",
        {"expected_substrings": ["rule.id:5710"], "forbidden_substrings": []},
    )
    assert not ok
    assert detail["missing_expected"] == ["rule.id:5710"]


def test_score_output_fail_when_forbidden_present():
    ok, detail = ct.score_output(
        "stdout has the bad value monitorprobe",
        {
            "expected_substrings": [],
            "forbidden_substrings": ["monitorprobe"],
        },
    )
    assert not ok
    assert detail["present_forbidden"] == ["monitorprobe"]


def _make_fixture(tmp_path: Path, rubric: dict) -> Path:
    f = tmp_path / "customization.yaml"
    f.write_text(
        yaml.safe_dump(
            {
                "cases": [
                    {
                        "id": "case-1",
                        "adaptation_note": "produce X",
                        "rubric": rubric,
                    }
                ]
            }
        )
    )
    return f


def _make_template(tmp_path: Path) -> Path:
    p = tmp_path / "tpl.md"
    p.write_text(TEMPLATE)
    return p


def test_run_file_passes_when_two_of_three_trials_pass(tmp_path: Path):
    """Pass on 2/3 — threshold is ceil(3*2/3) = 2."""
    rubric = {"expected_substrings": ["GOOD"], "forbidden_substrings": ["BAD"]}
    fixture = _make_fixture(tmp_path, rubric)
    template = _make_template(tmp_path)

    state = {"call": 0}
    outputs = ["GOOD ANSWER", "GOOD ANSWER", "no good answer here"]

    def invoker(prompt, *, log_dir, case_id):
        i = state["call"]
        state["call"] += 1
        return outputs[i]

    result = ct.run_file(
        template, fixture, trials=3, out_dir=tmp_path / "logs", invoker=invoker
    )
    assert result["verdict"] == "pass"
    case = result["cases"][0]
    assert case["passes"] == 2
    assert case["threshold"] == 2


def test_run_file_fails_when_only_one_of_three_passes(tmp_path: Path):
    rubric = {"expected_substrings": ["GOOD"], "forbidden_substrings": []}
    fixture = _make_fixture(tmp_path, rubric)
    template = _make_template(tmp_path)

    state = {"call": 0}
    outputs = ["GOOD", "no answer", "no answer"]

    def invoker(prompt, *, log_dir, case_id):
        i = state["call"]
        state["call"] += 1
        return outputs[i]

    result = ct.run_file(
        template, fixture, trials=3, out_dir=tmp_path / "logs", invoker=invoker
    )
    assert result["verdict"] == "fail"


def test_run_file_translates_invoker_errors_to_failed_trial(tmp_path: Path):
    rubric = {"expected_substrings": ["GOOD"], "forbidden_substrings": []}
    fixture = _make_fixture(tmp_path, rubric)
    template = _make_template(tmp_path)

    def invoker(prompt, *, log_dir, case_id):
        raise AgentStreamError("simulated subprocess crash")

    result = ct.run_file(
        template, fixture, trials=3, out_dir=tmp_path / "logs", invoker=invoker
    )
    case = result["cases"][0]
    assert case["passes"] == 0
    assert result["verdict"] == "fail"
    assert all(t.get("error") for t in case["trials_detail"])


def test_run_file_with_empty_cases_passes(tmp_path: Path):
    """No cases ≠ failure — verdict is pass (nothing to test, nothing broke)."""
    fixture = tmp_path / "customization.yaml"
    fixture.write_text(yaml.safe_dump({"cases": []}))
    template = _make_template(tmp_path)

    def invoker(prompt, *, log_dir, case_id):
        raise AssertionError("must not be called")

    result = ct.run_file(
        template, fixture, trials=3, out_dir=tmp_path / "logs", invoker=invoker
    )
    assert result["verdict"] == "pass"
    assert result["cases"] == []
