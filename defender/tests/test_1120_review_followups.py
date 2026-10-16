"""validate_scaffold serves against DEFENDER_DIR when set."""
from __future__ import annotations

from pathlib import Path

from defender.skills.connect import validate_scaffold
from defender.tests.tenant_1120_piece1 import _spec1120 as H


def _data_root_inside_another_code_tree(tmp_path: Path) -> tuple[Path, Path]:
    """A tenant adopted under `<tmp>/code/data`, with `<tmp>/code` the code tree an exported
    `DEFENDER_DIR` names. Returns `(the data root, the code tree)`."""
    code = tmp_path / "code"
    root = code / "data"
    H.adopted(root)
    return root, code


def test_validate_scaffold_holds_settings_outside_the_tree_it_checks(tmp_path: Path) -> None:
    """The same layout under `validate_scaffold` (advisory, M7): its config check is skipped
    with a WARN naming the settings as inside the exported tree."""
    root, code = _data_root_inside_another_code_tree(tmp_path)
    proc = H.run_script(H.script_of(validate_scaffold), "cmdb", "--tenant", H.TID,
                        root=root, DEFENDER_DIR=str(code))
    H.assert_ran(proc)
    text = H.output(proc)
    assert "config.env not checked" in text, text
    assert f"inside {code}" in text, text


