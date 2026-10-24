"""The box's code-check file travels in the oracle's runner files exactly once.

The source-reading rules that used to sit here (no disk credential location, a dormant tenant
delivery, the check-file name's single home and absence from agent-facing text) are held by
`tooling/lint/lint_delivery_architecture.py`."""
from __future__ import annotations


def test_code_check_file_is_one_of_the_oracles_runner_files():
    from defender import box
    from defender.box import _oracle
    name = box.CODE_CHECK_FILE
    assert [f for f in _oracle.RUNNER_FILES if name in f] == [f"defender/{name}"]
