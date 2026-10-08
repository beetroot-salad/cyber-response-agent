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


# check_frontiers

def _frontier(path: Path, name: str, meta: str, digest: str = "ok") -> None:
    (path / name).write_text(f"---\n{meta}---\n\n## Digest\n\n{digest}\n", encoding="utf-8")


def test_frontiers_bare_filename_input_is_accepted(tmp_path):
    # `inputs: [10-brief.md]` — the natural shorthand — is the contract's own spelling now.
    d = tmp_path / "frontiers"
    d.mkdir()
    _frontier(d, "10-brief.md", "phase: A\nstatus: complete\n")
    _frontier(d, "20-demands.md", "phase: A\nstatus: complete\ninputs: [10-brief.md]\n")
    p = run_script("check_frontiers.py", str(d), cwd=tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr


def test_frontiers_input_naming_no_file_is_flagged(tmp_path):
    d = tmp_path / "frontiers"
    d.mkdir()
    _frontier(d, "20-demands.md", "phase: A\nstatus: complete\ninputs: [{echo: 3}]\n")
    p = run_script("check_frontiers.py", str(d), cwd=tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "20-demands.md" in p.stdout and "names no file" in p.stdout


def test_frontiers_path_decorated_ref_to_a_missing_frontier_is_flagged(tmp_path):
    # `./10-brief.md` must resolve by bare filename — both to find it and to miss it.
    d = tmp_path / "frontiers"
    d.mkdir()
    _frontier(d, "20-demands.md",
              "phase: A\nstatus: complete\ninputs: [{path: ./10-brief.md}]\n")
    p = run_script("check_frontiers.py", str(d), cwd=tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "10-brief.md" in p.stdout


def test_frontiers_resume_reads_bare_filename_inputs_for_staleness(tmp_path):
    import os
    d = tmp_path / "frontiers"
    d.mkdir()
    _frontier(d, "10-brief.md", "phase: A\nstatus: complete\n")
    _frontier(d, "20-demands.md", "phase: A\nstatus: complete\ninputs: [10-brief.md]\n")
    os.utime(d / "20-demands.md", (1, 1))  # older than its input
    p = run_script("check_frontiers.py", str(d), "--resume", cwd=tmp_path)
    assert p.returncode == 0
    assert "STALE" in p.stdout and "20-demands.md" in p.stdout


def test_frontiers_string_count_is_a_finding_not_a_crash(tmp_path):
    # An optional inventory still carries integers; `consensus: "5"` is a finding, never
    # a traceback that loses the whole report.
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


# check_frontiers --only: a leaf lints its own frontier before returning, while its
# phase siblings may still be half-written beside it.

def _only_chain(d: Path) -> None:
    d.mkdir()
    _frontier(d, "20-demands.md", "phase: A\nstatus: complete\ninventory: {demands: 4}\n")
    _frontier(d, "30-premises-author.md",
              "phase: B\nstatus: complete\ninventory: {premises: 7}\n"
              "inputs: [20-demands.md]\n")
    # A sibling lens mid-write: its digest overruns the cap.
    _frontier(d, "30-premises-dependency.md",
              "phase: B\nstatus: complete\ninventory: {premises: 3}\n",
              digest="\n".join(f"line {i}" for i in range(20)))


def test_frontiers_only_ignores_a_broken_sibling(tmp_path):
    d = tmp_path / "frontiers"
    _only_chain(d)
    p = run_script("check_frontiers.py", str(d), "--only", "30-premises-author.md",
                   cwd=tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "30-premises-dependency.md" not in p.stdout


def test_frontiers_only_reports_the_named_file(tmp_path):
    d = tmp_path / "frontiers"
    _only_chain(d)
    p = run_script("check_frontiers.py", str(d), "--only", "30-premises-dependency.md",
                   cwd=tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "30-premises-dependency.md" in p.stdout and "digest" in p.stdout


def test_frontiers_only_still_resolves_inputs_against_the_chain(tmp_path):
    # The named file's inputs are looked up in the chain, which the flag must still load.
    d = tmp_path / "frontiers"
    _only_chain(d)
    _frontier(d, "30-premises-author.md",
              "phase: B\nstatus: complete\ninputs: [21-demands.md]\n")
    p = run_script("check_frontiers.py", str(d), "--only", "30-premises-author.md",
                   cwd=tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "21-demands.md" in p.stdout


def test_frontiers_only_naming_no_frontier_exits_2(tmp_path):
    # A typo'd name must not read as a clean pass.
    d = tmp_path / "frontiers"
    _only_chain(d)
    p = run_script("check_frontiers.py", str(d), "--only", "30-premises-autor.md",
                   cwd=tmp_path)
    assert p.returncode == 2, p.stdout + p.stderr


def test_frontiers_only_naming_a_sidecar_payload_exits_2(tmp_path):
    # A `.py` payload exists on disk but is no frontier — its `.md` sidecar is what gets
    # linted. Naming the payload must not read as a clean pass over nothing.
    d = tmp_path / "frontiers"
    _only_chain(d)
    (d / "42-answers-copy1.py").write_text("def test_x():\n    pass\n", encoding="utf-8")
    p = run_script("check_frontiers.py", str(d), "--only", "42-answers-copy1.py",
                   cwd=tmp_path)
    assert p.returncode == 2, p.stdout + p.stderr


# trace

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
