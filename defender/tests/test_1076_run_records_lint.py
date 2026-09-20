"""The run-records inventory gate: scripts/lint/lint_run_records.py (#1076).

Same shape as the other lint suites — the gate is a standalone program under repo-root
``scripts/lint/``, reached by path. What is pinned: the sweep finds a file-access call by its
RESOLVED callee (an aliased from-import counts, a docstring mention does not); a site with no
row and a row whose call is gone are both findings; a `names` row is evidence, not a call;
and the page is a render of the two tables, so a table edit without `--render` fails.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests._by_path import load_lint_gate

_GATE = load_lint_gate("lint_run_records")


def _write(tmp: Path, rel: str, text: str) -> None:
    p = tmp / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_sweep_resolves_callee_not_spelling(tmp_path: Path) -> None:
    _write(tmp_path, "runtime/a.py",
           "from shutil import copy2 as cp\n"
           "from pathlib import Path\n"
           "\n"
           "def archive(src, dst):\n"
           "    '''Not a site: open(x) in prose.'''\n"
           "    cp(src, dst)\n"
           "    return Path(dst).read_text()\n")
    sites = _GATE.scan(tmp_path)
    assert [(s.function, s.what, s.opclass) for s in sites] == [
        ("archive", "shutil.copy2", "copy"),
        ("archive", ".read_text", "read"),
    ]


def test_unattributed_and_stale_are_findings() -> None:
    sites = [_GATE.Site("runtime/a.py", 3, "f", "builtins.open", "open")]
    rows = [_GATE.Row("runtime/b.py", 9, "alert", "read", "g", ".read_text", "live", "")]
    found = {f.fingerprint for f in _GATE.findings(sites, rows)}
    assert found == {"runtime/a.py::f::builtins.open", "stale::runtime/b.py::g::.read_text"}


def test_second_call_in_an_attributed_function_is_still_a_finding() -> None:
    # The first version keyed on path::function and let any extra call hide behind one row.
    sites = [_GATE.Site("runtime/a.py", 3, "f", "defender._io.guarded_mkdir", "write"),
             _GATE.Site("runtime/a.py", 4, "f", "defender._io.guarded_mkdir", "write")]
    rows = [_GATE.Row("runtime/a.py", 3, "alert", "mkdir", "f", "defender._io.guarded_mkdir", "host", "")]
    assert [f.fingerprint for f in _GATE.findings(sites, rows)] == ["runtime/a.py::f::defender._io.guarded_mkdir"]


def test_op_must_fit_the_callee_and_kind_must_be_known() -> None:
    sites = [_GATE.Site("runtime/a.py", 3, "f", ".read_text", "read")]
    rows = [_GATE.Row("runtime/a.py", 3, "nosuch", "write", "f", ".read_text", "live", "")]
    kinds = [{"kind": "alert"}]
    fps = sorted(f.fingerprint for f in _GATE.findings(sites, rows, kinds))
    assert fps == ["kind::runtime/a.py::f::.read_text::nosuch", "op::runtime/a.py::f::.read_text::write"]


def test_names_row_is_evidence_not_a_call() -> None:
    rows = [_GATE.Row("learning/x.py", 1, "stage_trace", _GATE.NAMES_OP, "wiring", "", "live", "")]
    assert _GATE.findings([], rows) == []


def test_refresh_repoints_lines_within_the_function() -> None:
    sites = [_GATE.Site("runtime/a.py", 30, "f", ".read_text", "read"),
             _GATE.Site("runtime/a.py", 41, "f", ".write_text", "write")]
    rows = [_GATE.Row("runtime/a.py", 12, "alert", "read", "f", ".read_text", "live", ""),
            _GATE.Row("runtime/a.py", 20, "report", "write", "f", ".write_text", "end", "")]
    assert _GATE.refresh_lines(rows, sites) == 2
    assert [r.line for r in rows] == [30, 41]


@pytest.mark.gate
def test_checked_in_page_is_the_render_of_its_tables() -> None:
    rows = _GATE.load_rows()
    kinds = _GATE.load_kinds()
    page = _GATE.PAGE.read_text(encoding="utf-8")
    assert _GATE.render_page(rows, kinds, page).split("## Appendix")[0] == page.split("## Appendix")[0]
    assert page.endswith(_GATE.render_appendix(rows) + "\n")
    assert _GATE.findings(_GATE.scan(), rows, kinds) == []
