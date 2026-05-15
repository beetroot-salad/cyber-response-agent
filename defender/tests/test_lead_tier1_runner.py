"""End-to-end Tier 1 runner with a mocked customization invoker.

Verifies:
  * static + customization legs combine into a single verdict
  * a missing customization.yaml is ``skipped`` (not a failure)
  * the ``TIER1_RESULT:`` line parses as JSON
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from defender.learning import lead_tier1


_TEMPLATE = """---
id: wazuh.fakeops
---

## Goal

g

## What to characterize

- one

## Query

```bash
python3 defender/scripts/tools/wazuh_cli.py query --query 'rule.id:5710'
```

`${rule_id}` is the rule id; pass it as a numeric string.

## Filter binding

- `rule_id` → the numeric Wazuh rule id.

## Common pitfalls

- none
"""


def _seed(qroot: Path) -> Path:
    """Write a wazuh template + matching customization fixture under ``qroot``."""
    sysroot = qroot / "wazuh"
    sysroot.mkdir(parents=True)
    tpl = sysroot / "fakeops.md"
    tpl.write_text(_TEMPLATE)

    fixtures = qroot / "tests" / "wazuh" / "fakeops"
    fixtures.mkdir(parents=True)
    (fixtures / "customization.yaml").write_text(
        yaml.safe_dump(
            {
                "cases": [
                    {
                        "id": "trivial",
                        "adaptation_note": "produce X",
                        "rubric": {
                            "expected_substrings": ["GOOD"],
                            "forbidden_substrings": [],
                        },
                    }
                ]
            }
        )
    )
    return tpl


def test_runner_combines_static_and_customization(
    tmp_path: Path, monkeypatch
):
    qroot = tmp_path / "queries"
    tpl = _seed(qroot)
    monkeypatch.setattr(lead_tier1, "CATALOG_ROOT", qroot)
    monkeypatch.setattr(lead_tier1, "TESTS_ROOT", qroot / "tests")

    def invoker(prompt, *, log_dir, case_id):
        return "GOOD output"

    result = lead_tier1.run_tier1(
        tpl, trials=3, out_dir=tmp_path / "logs", customization_invoker=invoker
    )
    assert result["verdict"] == "pass"
    assert result["static"]["passed"]
    assert result["customization"]["verdict"] == "pass"


def test_runner_fails_when_customization_fails(tmp_path: Path, monkeypatch):
    qroot = tmp_path / "queries"
    tpl = _seed(qroot)
    monkeypatch.setattr(lead_tier1, "CATALOG_ROOT", qroot)
    monkeypatch.setattr(lead_tier1, "TESTS_ROOT", qroot / "tests")

    def invoker(prompt, *, log_dir, case_id):
        return "wrong"

    result = lead_tier1.run_tier1(
        tpl, trials=3, out_dir=tmp_path / "logs", customization_invoker=invoker
    )
    assert result["verdict"] == "fail"
    assert result["static"]["passed"]
    assert result["customization"]["verdict"] == "fail"


def test_runner_skips_customization_when_no_fixture(tmp_path: Path, monkeypatch):
    qroot = tmp_path / "queries"
    sysroot = qroot / "wazuh"
    sysroot.mkdir(parents=True)
    tpl = sysroot / "isolated.md"
    tpl.write_text(_TEMPLATE.replace("wazuh.fakeops", "wazuh.isolated"))
    monkeypatch.setattr(lead_tier1, "CATALOG_ROOT", qroot)
    monkeypatch.setattr(lead_tier1, "TESTS_ROOT", qroot / "tests")

    result = lead_tier1.run_tier1(tpl, trials=3)
    assert result["verdict"] == "pass"
    assert result["customization"]["verdict"] == "skipped"


def test_runner_fails_on_static_regardless_of_customization(
    tmp_path: Path, monkeypatch
):
    qroot = tmp_path / "queries"
    tpl = _seed(qroot)
    # Break the static check: rewrite frontmatter id so it disagrees with path.
    tpl.write_text(tpl.read_text().replace("wazuh.fakeops", "wazuh.misnamed"))
    monkeypatch.setattr(lead_tier1, "CATALOG_ROOT", qroot)
    monkeypatch.setattr(lead_tier1, "TESTS_ROOT", qroot / "tests")

    def invoker(prompt, *, log_dir, case_id):
        return "GOOD"

    result = lead_tier1.run_tier1(
        tpl, trials=3, out_dir=tmp_path / "logs", customization_invoker=invoker
    )
    assert result["verdict"] == "fail"
    assert not result["static"]["passed"]


def test_main_emits_parseable_result_line(tmp_path: Path, monkeypatch, capsys):
    """``TIER1_RESULT: { ... }`` final line is JSON-parseable."""
    qroot = tmp_path / "queries"
    sysroot = qroot / "wazuh"
    sysroot.mkdir(parents=True)
    tpl = sysroot / "isolated.md"
    tpl.write_text(_TEMPLATE.replace("wazuh.fakeops", "wazuh.isolated"))
    monkeypatch.setattr(lead_tier1, "CATALOG_ROOT", qroot)
    monkeypatch.setattr(lead_tier1, "TESTS_ROOT", qroot / "tests")

    rc = lead_tier1.main([str(tpl), "--trials", "3"])
    assert rc == 0
    out = capsys.readouterr().out
    match = re.search(r"TIER1_RESULT:\s*(\{.+?\})\s*$", out, re.DOTALL)
    assert match, out
    payload = json.loads(match.group(1))
    assert payload["verdict"] == "pass"


def test_main_returns_2_on_missing_file(tmp_path: Path):
    rc = lead_tier1.main([str(tmp_path / "absent.md")])
    assert rc == 2
