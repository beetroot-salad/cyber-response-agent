"""#629 — the investigation.md size-bound legs of `tests/spec_graph_629-report-output-structure.yaml`
that survive #774 unchanged: the mid-run lifecycle legs (lc1-lc3).

R1 (#774) removes report.md from `write_file`/`edit_file`'s write allow entirely — the close
tool is now its sole writer — which retires every report.md-specific demand this file used to
carry (D4-D6, wm1-wm5, ii3, D5, lc6): their premise was "content-dependent refusal on
write_file/edit_file", and that entry point now refuses report.md unconditionally, regardless
of content. Those demands are retired with their reason in
`tests/spec_graph_629-report-output-structure.yaml` (see the `#774-retired` notes there) rather
than discovered as a broken test; the properties they pinned that #774 still owes are
re-expressed on the close tool in `tests/test_774_close_tool.py`.

investigation.md stays fully model-writable through both tools, so its size-bound legs are
untouched by R1 and still belong here, driving the REAL `_tool_write_file`/`_tool_edit_file`
(through the real `bind` seam), matching this file's original discipline: fakes enter only
through injection seams, never `monkeypatch.setattr`.
"""
from __future__ import annotations


import pytest

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
    """lc1 — at turn K only that call's full resulting text is evaluated: an under-bound
    investigation commits, then an over-bound (but invlang-valid) write on the next turn is
    denied for THAT call only, leaving the K-1 committed content untouched on disk."""
    deps, run = _deps(tmp_path)
    p = str(run / "investigation.md")
    runtime_tools._tool_write_file(deps, p, GOLDEN_INV)
    over = GOLDEN_INV.rstrip() + "\n" + "x" * (INV_BOUND + 5000) + "\n"
    with pytest.raises(ModelRetry):
        runtime_tools._tool_write_file(deps, p, over)
    assert (run / "investigation.md").read_text(encoding="utf-8") == GOLDEN_INV


def test_edit_file_splice_pushes_investigation_over_bound(tmp_path):
    """lc2 — an edit_file splice that pushes investigation.md past 65,536 B is denied: the gate
    sees the post-splice WHOLE resulting text, not the delta. The splice is an append (invlang
    append-only-valid) so the deny is the NEW size check, not invlang. Prior content preserved."""
    deps, run = _deps(tmp_path)
    p = str(run / "investigation.md")
    runtime_tools._tool_write_file(deps, p, GOLDEN_INV)
    current = (run / "investigation.md").read_text(encoding="utf-8")
    anchor = current.rstrip()[-40:]
    assert current.count(anchor) == 1, "re-probe: the edit anchor is unique"
    with pytest.raises(ModelRetry):
        runtime_tools._tool_edit_file(deps, p, anchor, anchor + "\n" + "x" * (INV_BOUND + 5000))
    assert (run / "investigation.md").read_text(encoding="utf-8") == current


def test_edit_file_splice_pulls_investigation_under_bound(tmp_path):
    """lc3 — a shrinking splice landing <= 65,536 B is accepted regardless of the stale
    over-bound baseline it started from (Decision(True), invlang also passing). A grandfathered
    over-bound investigation on disk is edited down under the bound and the edit commits."""
    deps, run = _deps(tmp_path)
    p = str(run / "investigation.md")
    pad = "x" * (INV_BOUND + 5000)
    over = GOLDEN_INV.rstrip() + "\n" + pad + "\n"
    (run / "investigation.md").write_text(over, encoding="utf-8")
    runtime_tools._tool_edit_file(deps, p, "\n" + pad + "\n", "\n")
    shrunk = (run / "investigation.md").read_text(encoding="utf-8")
    assert len(shrunk.encode("utf-8")) <= INV_BOUND
    assert pad not in shrunk
