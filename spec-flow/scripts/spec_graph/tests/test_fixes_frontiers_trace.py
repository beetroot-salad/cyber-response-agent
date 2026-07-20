"""Regression suite for the PR #674 review fixes in check_frontiers and trace.

Same house style as test_mechanical_checks: every test drives the real script via
subprocess and asserts on the exit code plus the identity of the element named in the
finding, never exact wording. Exit contract: 0 clean, 1 looked and found something,
2 could not look (never a silent pass).
"""
from __future__ import annotations

import json
from pathlib import Path

from conftest import SPEC_GRAPH_DIR  # noqa: F401 — the import wires PYTHONPATH conventions
from test_mechanical_checks import run_script


# ---------------------------------------------------------------------------
# check_frontiers
# ---------------------------------------------------------------------------

def _frontier(path: Path, name: str, meta: str, digest: str = "ok") -> None:
    (path / name).write_text(f"---\n{meta}---\n\n## Digest\n\n{digest}\n", encoding="utf-8")


def test_frontiers_non_dict_input_entry_is_flagged(tmp_path):
    # `inputs: [10-brief.md]` — the natural shorthand — used to be silently dropped by the
    # dict filter: no echo reconciliation, no finding. It must now be a finding.
    d = tmp_path / "frontiers"
    d.mkdir()
    _frontier(d, "10-brief.md", "phase: A\nstatus: complete\ninventory: {claims: 3}\n")
    _frontier(d, "20-demands.md",
              "phase: A\nstatus: complete\ninventory: {demands: 2}\n"
              "inputs: [10-brief.md]\n")
    p = run_script("check_frontiers.py", str(d), cwd=tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "10-brief.md" in p.stdout and "mapping" in p.stdout


def test_frontiers_path_decorated_ref_still_reconciles_the_echo(tmp_path):
    # `path: ./10-brief.md` used to miss the bare-filename producer lookup AND the
    # numeric-prefix classification — a wrong echo behind a decorated ref escaped silently.
    d = tmp_path / "frontiers"
    d.mkdir()
    _frontier(d, "10-brief.md", "phase: A\nstatus: complete\ninventory: {claims: 3}\n")
    _frontier(d, "20-demands.md",
              "phase: A\nstatus: complete\ninventory: {demands: 2}\n"
              "inputs: [{path: ./10-brief.md, inventory_echo: {claims: 4}}]\n")
    p = run_script("check_frontiers.py", str(d), cwd=tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "inventory_echo" in p.stdout and "10-brief.md" in p.stdout


def test_frontiers_partial_dispositions_are_flagged_and_summed(tmp_path):
    # Three of the four mandated disposition keys, summing 24 against 27 premises consumed:
    # the old all-four gate skipped the rule entirely and the chain exited 0.
    d = tmp_path / "frontiers"
    d.mkdir()
    _frontier(d, "40-premises.md", "phase: C\nstatus: complete\ninventory: {premises: 27}\n")
    _frontier(d, "45-dispositions.md",
              "phase: C\nstatus: complete\n"
              "inventory: {consensus: 20, forks: 2, drops: 2}\n"
              "inputs: [{path: 40-premises.md, inventory_echo: {premises: 27}}]\n")
    p = run_script("check_frontiers.py", str(d), cwd=tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "silent_branches" in p.stdout          # the missing mandated key is named
    assert "24" in p.stdout and "27" in p.stdout  # the sum runs over what is present


def test_frontiers_string_count_is_a_finding_not_a_crash(tmp_path):
    # `consensus: "5"` used to raise TypeError inside the dispositions sum, losing the
    # whole report behind a traceback. The non-int finding fires; the sum skips it.
    d = tmp_path / "frontiers"
    d.mkdir()
    _frontier(d, "40-premises.md", "phase: C\nstatus: complete\ninventory: {premises: 10}\n")
    _frontier(d, "45-dispositions.md",
              "phase: C\nstatus: complete\n"
              'inventory: {consensus: "5", forks: 2, silent_branches: 1, drops: 1}\n'
              "inputs: [{path: 40-premises.md, inventory_echo: {premises: 10}}]\n")
    p = run_script("check_frontiers.py", str(d), cwd=tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "Traceback" not in p.stderr
    assert "consensus" in p.stdout                # the non-int count is flagged
    assert "[check_frontiers]" in p.stdout        # the report survived to its summary line


# ---------------------------------------------------------------------------
# trace
# ---------------------------------------------------------------------------

def test_trace_drivers_bad_base_ref_exits_2(make_repo):
    # A nonexistent/unfetched base made `git diff` exit 128 with empty stdout, which read
    # as "no changed census modules", exit 0 — could-not-look presented as answered.
    r = make_repo()
    r.config(code_roots=["app"], entrypoint_stems=("run",))
    r.write("app/run.py", "if __name__ == '__main__':\n    pass\n")
    r.commit("base")
    p = run_script("trace.py", "drivers", "--base", "no-such-ref", cwd=r.root)
    assert p.returncode == 2, p.stdout + p.stderr
    assert "no-such-ref" in p.stderr


def _resource_config(r, resources: dict) -> None:
    r.write(".claude/spec-flow.json", json.dumps({"specGraph": {
        "artifacts": "**/spec_graph_*.yaml", "codeRoots": ["app"],
        "entrypointStems": [], "contextAliases": {}, "conceptAliases": {},
        "resources": resources,
    }}))


def test_trace_resource_sees_a_writer_in_tests_conftest(make_repo):
    # The execution-context census excludes tests/ — a writer in tests/conftest.py was
    # TOTALLY absent from the resource report (no line, no floor), violating NON-1.
    r = make_repo()
    _resource_config(r, {"log": {"writers": ["app/io.py::append_row"]}})
    r.write("app/io.py", "def append_row(p, row):\n    pass\n")
    r.write("tests/conftest.py",
            "from app.io import append_row\n\n\ndef seed(d):\n    append_row(d / 'x.jsonl', {})\n")
    r.commit("c")
    p = run_script("trace.py", "resource", "log", cwd=r.root)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "tests/conftest.py" in p.stdout  # reported — resolved writer or floor, never dropped


def test_trace_resource_unresolved_sink_exits_2(make_repo):
    # A declared sink whose file is missing printed UNRESOLVED but still exited 0 — a
    # census that looked at nothing reported success.
    r = make_repo()
    _resource_config(r, {"log": {"writers": ["app/gone.py::append_row"]}})
    r.write("app/other.py", "X = 1\n")
    r.commit("c")
    p = run_script("trace.py", "resource", "log", cwd=r.root)
    assert p.returncode == 2, p.stdout + p.stderr
    assert "UNRESOLVED" in p.stdout and "app/gone.py::append_row" in p.stdout


def test_trace_drivers_floors_a_reexec_from_a_non_entrypoint(make_repo):
    # cli.py -> runner.py, and runner.py (NOT an entrypoint) re-execs the changed paths.py:
    # no driver edge exists (the subproc scan covers only entrypoints), so the relocated-
    # PATHS class used to escape with no line at all. It must now appear as floor.
    r = make_repo()
    r.config(code_roots=["app"], entrypoint_stems=("cli",))
    r.write("app/cli.py", "import app.runner\n")
    r.write("app/runner.py",
            "import subprocess\nimport sys\n\n\ndef go():\n"
            "    subprocess.run([sys.executable, 'app/paths.py'])\n")
    r.write("app/paths.py", "ANCHOR = 'a'\n")
    base = r.commit("base")
    r.write("app/paths.py", "ANCHOR = 'b'\n")
    r.commit("change")
    p = run_script("trace.py", "drivers", "--base", base, cwd=r.root)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "app/runner.py" in p.stdout
    assert "paths" in p.stdout and "classify by hand" in p.stdout
