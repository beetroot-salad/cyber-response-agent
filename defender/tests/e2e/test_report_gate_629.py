"""#629 — the investigation.md size-bound legs of `tests/spec_graph_629-report-output-structure.yaml`
that survive #774 unchanged: the mid-run lifecycle legs (lc1-lc3)."""
from __future__ import annotations


import pytest

from defender.tests.support.runtime.state._1255_view import model_path

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender.agents import MAIN_DEF  # noqa: E402
from defender.runtime import tools as runtime_tools  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.tests.e2e._replay_harness import GOLDEN_AB3  # noqa: E402

pytestmark = pytest.mark.e2e

INV_BOUND = 65536
GOLDEN_INV = (GOLDEN_AB3 / "investigation.md").read_text(encoding="utf-8")


def _deps(tmp_path):
    """MAIN deps through the real `bind` seam — the real compiled policy + gate; nothing faked
    at the gate. No box: the file tools never touch the bash execution boundary."""
    run = tmp_path / "run"
    run.mkdir()
    dfn = tmp_path / "defender"
    dfn.mkdir()
    return bind(MAIN_DEF, run, defender_dir=dfn), run


def test_investigation_crosses_bound_mid_run(tmp_path):
    deps, run = _deps(tmp_path)
    p = model_path(run / "investigation.md", run_dir=run)   # #1255 P1: the model's spelling
    runtime_tools._tool_write_file(deps, p, GOLDEN_INV)
    over = GOLDEN_INV.rstrip() + "\n" + "x" * (INV_BOUND + 5000) + "\n"
    with pytest.raises(ModelRetry):
        runtime_tools._tool_write_file(deps, p, over)
    assert (run / "investigation.md").read_text(encoding="utf-8") == GOLDEN_INV


def test_edit_file_splice_pushes_investigation_over_bound(tmp_path):
    deps, run = _deps(tmp_path)
    p = model_path(run / "investigation.md", run_dir=run)   # #1255 P1: the model's spelling
    runtime_tools._tool_write_file(deps, p, GOLDEN_INV)
    current = (run / "investigation.md").read_text(encoding="utf-8")
    anchor = current.rstrip()[-40:]
    assert current.count(anchor) == 1, "re-probe: the edit anchor is unique"
    with pytest.raises(ModelRetry):
        runtime_tools._tool_edit_file(deps, p, anchor, anchor + "\n" + "x" * (INV_BOUND + 5000))
    assert (run / "investigation.md").read_text(encoding="utf-8") == current


def test_edit_file_splice_pulls_investigation_under_bound(tmp_path):
    deps, run = _deps(tmp_path)
    p = model_path(run / "investigation.md", run_dir=run)   # #1255 P1: the model's spelling
    pad = "x" * (INV_BOUND + 5000)
    over = GOLDEN_INV.rstrip() + "\n" + pad + "\n"
    (run / "investigation.md").write_text(over, encoding="utf-8")
    runtime_tools._tool_edit_file(deps, p, "\n" + pad + "\n", "\n")
    shrunk = (run / "investigation.md").read_text(encoding="utf-8")
    assert len(shrunk.encode("utf-8")) <= INV_BOUND
    assert pad not in shrunk
