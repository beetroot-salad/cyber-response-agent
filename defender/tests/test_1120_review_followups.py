"""#1120 piece 1 — the small follow-ups from the code review on PR #1157.

  * Finding 10: `validate_scaffold` serves against `$DEFENDER_DIR` when it is set, so step 7
    holds the tenant's settings outside THAT tree — not only outside the package's own
    `defender/`, which the command may not be running against. (The finding also named
    `ticket_adapter`, whose command line #1107 has since removed.)
  * Finding 12: the census lint reports a clean table from the rows it judged; it does not
    load the table a second time to count the gather grants.
"""
from __future__ import annotations

from pathlib import Path

from defender import _tenant_census
from defender.skills.connect import validate_scaffold
from defender.tests._by_path import load_lint_gate
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


def test_the_census_lint_loads_each_table_once(monkeypatch) -> None:
    """Over the real repo, every table the lint judges is loaded exactly once: the clean
    report's gather count comes from the judged rows."""
    lint = load_lint_gate("lint_verb_disposition_census",
                          name="lint_verb_disposition_census_1120_followups")
    loaded: list[Path] = []
    real = _tenant_census.load_dispositions

    def counting(path: Path):
        loaded.append(Path(path))
        return real(path)

    # A spy, not a fake: it counts reads and returns the real loader's rows. No seam carries
    # the loader, and a second read is only visible by counting. The lint's own name is
    # patched too, so a lint that loads the table itself again is counted.
    monkeypatch.setattr(_tenant_census, "load_dispositions", counting)  # lint-monkeypatch: ok — a counting spy over the real loader; no seam carries it
    if hasattr(lint, "load_dispositions"):
        monkeypatch.setattr(lint, "load_dispositions", counting)  # lint-monkeypatch: ok — the same spy, on the lint's own import
    assert lint.main(["--root", str(H.REPO_ROOT)]) == 0
    assert loaded, "the lint loaded no table at all"
    assert len(loaded) == len(set(loaded)), f"a table was loaded more than once: {loaded}"
