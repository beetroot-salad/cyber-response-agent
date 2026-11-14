"""#1503: no agent reads the checkout's `tests/`. It holds the fixture tenant (its `settings/`
included) and lab snapshots, test data no run reads. A run dir a test placed under `tests/`
stays readable as the run's own."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.agents import MAIN_DEF  # noqa: E402
from defender.investigation import permission  # noqa: E402
from defender.investigation.agent_definition import compile_policy_for  # noqa: E402
from defender.investigation.permission.files import read_allowed_path  # noqa: E402


def _tree(tmp_path: Path) -> tuple[Path, Path]:
    dfn = tmp_path / "defender"
    for rel in ("lessons/x.md", "tests/fixtures/tenant-fixture/settings/verb-grants.yaml",
                "tests/fixtures/pre-p4-shipped/agent/lessons/y.md", "testsuite/z.md"):
        (dfn / rel).parent.mkdir(parents=True, exist_ok=True)
        (dfn / rel).write_text("x\n", encoding="utf-8")
    run = tmp_path / "run"
    run.mkdir()
    return dfn, run


def _readable(path: Path, *, run: Path, dfn: Path) -> tuple[bool, bool]:
    policy = compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn)
    return (permission.decide_read(path, run_dir=run, defender_dir=dfn, policy=policy).allow,
            read_allowed_path(path, run_dir=run, defender_dir=dfn, policy=policy))


@pytest.mark.parametrize("rel", ["tests/fixtures/tenant-fixture/settings/verb-grants.yaml",
                                 "tests/fixtures/pre-p4-shipped/agent/lessons/y.md"])
def test_both_read_surfaces_deny_the_checkouts_tests(tmp_path, rel):
    dfn, run = _tree(tmp_path)
    assert _readable(dfn / "lessons" / "x.md", run=run, dfn=dfn) == (True, True), "control"
    assert _readable(dfn / rel, run=run, dfn=dfn) == (False, False)


def test_a_sibling_whose_name_starts_with_tests_is_not_denied(tmp_path):
    dfn, run = _tree(tmp_path)
    assert _readable(dfn / "testsuite" / "z.md", run=run, dfn=dfn)[1] is True


def test_a_run_dir_placed_under_tests_stays_readable(tmp_path):
    dfn, _ = _tree(tmp_path)
    run = dfn / "tests" / "fixtures" / "e2e" / "some-run"
    run.mkdir(parents=True)
    (run / "investigation.md").write_text("x\n", encoding="utf-8")
    assert _readable(run / "investigation.md", run=run, dfn=dfn) == (True, True)
