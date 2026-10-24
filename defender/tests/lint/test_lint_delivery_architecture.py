"""Tests for the lint_delivery_architecture gate: no disk credential location, a dormant tenant
delivery, and a box check-file name spelled once inside the box package."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.support.shared.contracts._by_path import load_lint_gate

_GATE = load_lint_gate("lint_delivery_architecture")

_SPEC = 'CODE_CHECK_FILE = "MOUNT_CHECK"\n'


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "defender"
    for rel, text in {"box/_spec.py": _SPEC, **files}.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def test_a_clean_tree_has_no_findings(tmp_path):
    assert _GATE.scan(_tree(tmp_path, {"learning/x.py": "x = 1\n"})) == []


@pytest.mark.parametrize("src", [
    'P = "git-credentials"\n',
    'P = ".git" + "-credentials"\n',
    'P = "/".join(["~", "git-credentials"])\n',
    'P = f"{HOME}/git-credentials"\n',
])
def test_a_credential_location_is_found_however_the_name_is_spelled(tmp_path, src):
    found = _GATE.scan(_tree(tmp_path, {"learning/x.py": src}))
    assert len(found) == 1 and "git-credentials" in found[0], found


def test_a_docstring_may_mention_the_credential_name(tmp_path):
    assert _GATE.scan(_tree(tmp_path, {"learning/x.py": '"""Never git-credentials."""\n'})) == []


@pytest.mark.parametrize("src", [
    "from defender.learning.author.version_control import TenantDelivery\n",
    "from defender.learning.author.version_control.tenant_delivery import go\n",
    "x = TenantDelivery\n",
    "y = 'tenant_delivery'\n",
])
def test_delivery_named_outside_its_owner_is_found(tmp_path, src):
    found = _GATE.scan(_tree(tmp_path, {"learning/x.py": src}))
    assert found and all("TenantDelivery" in f for f in found), found


def test_delivery_named_inside_its_owner_is_allowed(tmp_path):
    owner = "learning/author/version_control/delivery.py"
    assert _GATE.scan(_tree(tmp_path, {owner: "class TenantDelivery: ...\n"})) == []


def test_tests_are_not_swept(tmp_path):
    assert _GATE.scan(_tree(tmp_path, {"tests/t.py": 'P = "git-credentials"\nx = TenantDelivery\n'})) == []


def test_the_check_file_name_spelled_a_second_time_outside_the_spec_is_found(tmp_path):
    root = _tree(tmp_path, {"learning/x.py": 'N = "MOUNT_CHECK"\n'})
    found = _GATE.scan(root)
    assert any("exactly once" in f and "found 2" in f for f in found), found


@pytest.mark.parametrize("rel", ["prompts/a.md", "prompts/b.j2", "knowledge_note.yaml"])
def test_agent_facing_text_must_not_name_the_check_file(tmp_path, rel):
    found = _GATE.scan(_tree(tmp_path, {rel: "read MOUNT_CHECK first\n"}))
    assert len(found) == 1 and "agent-facing" in found[0], found


def test_operator_docs_and_the_docs_folder_may_name_it(tmp_path):
    files = {"README.md": "MOUNT_CHECK\n", "docs/a.md": "MOUNT_CHECK\n"}
    assert _GATE.scan(_tree(tmp_path, files)) == []


def test_the_shipped_knowledge_trees_agent_halves_are_swept(tmp_path):
    root = _tree(tmp_path, {})
    note = tmp_path / "knowledge" / "tenant-template" / "agent" / "n.txt"
    note.parent.mkdir(parents=True)
    note.write_text("MOUNT_CHECK", encoding="utf-8")
    found = _GATE.scan(root)
    assert len(found) == 1 and "knowledge/tenant-template/agent/n.txt" in found[0], found


def test_a_missing_spec_constant_is_a_finding_not_a_pass(tmp_path):
    found = _GATE.scan(_tree(tmp_path, {"box/_spec.py": "OTHER = 1\n"}))
    assert any("CODE_CHECK_FILE" in f for f in found), found


def test_an_unparseable_module_is_blind_not_skipped(tmp_path):
    with pytest.raises(_GATE._astlib.ScanBlind):
        _GATE.scan(_tree(tmp_path, {"learning/x.py": "def (:\n"}))
