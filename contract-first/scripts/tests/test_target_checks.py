"""check_calls and check_stub against a suite whose target is not written yet."""
from __future__ import annotations

import sys
import textwrap

from conftest import run_script


def _suite_repo(make_repo):
    """A fixture repo whose suite imports `appx.summarize` — a project-rooted module
    that does not exist: the not-yet-written target."""
    r = make_repo()
    r.write("appx/helper.py", "def existing():\n    return 1\n")
    r.write("tests/spec/test_spec.py", textwrap.dedent("""\
        from appx.summarize import summarize


        def _drive(path):
            return summarize(path)


        def test_returns_the_summary():
            \"\"\"summarize returns the text of the summary.\"\"\"
            assert _drive("a.txt") == "the summary"


        def test_nothing_about_the_target():
            \"\"\"a vacuous negative — green against any implementation.\"\"\"
            assert "secret" not in ""
    """))
    return r


def test_calls_flags_the_test_that_never_reaches_the_target(make_repo):
    r = _suite_repo(make_repo)
    p = run_script("check_calls.py", str(r.root / "tests/spec"), cwd=r.root)
    assert p.returncode == 1
    assert "test_nothing_about_the_target" in p.stdout
    assert "test_returns_the_summary" not in p.stdout  # reaches it through _drive


def test_calls_with_no_identifiable_target_exits_2(make_repo):
    r = make_repo()
    r.write("appx/helper.py", "def existing():\n    return 1\n")
    r.write("tests/spec/test_spec.py",
            "from appx.helper import existing\n\n\ndef test_a():\n    assert existing() == 1\n")
    p = run_script("check_calls.py", str(r.root / "tests/spec"), cwd=r.root)
    assert p.returncode == 2


def test_nullstub_discriminates_and_flags_the_vacuous_pass(make_repo):
    r = _suite_repo(make_repo)
    p = run_script(
        "check_stub.py", str(r.root / "tests/spec"), "--python", sys.executable, cwd=r.root,
    )
    assert p.returncode == 1, p.stdout + p.stderr
    assert "NULLSTUB-PASS" in p.stdout and "test_nothing_about_the_target" in p.stdout
    assert "1 discriminating" in p.stdout  # the real test failed on its own assertion


def test_a_directory_of_helpers_with_no_tests_is_refused(make_repo):
    """The guard asks whether pytest would COLLECT anything, not whether the directory holds
    `.py`. A suite of only `conftest.py` and helpers passes a bare-Python test while collecting
    nothing, and the run then prints its clean line — `0 test(s) that never reach the target`,
    exit 0 — over a suite with no tests in it. That is the #949 false clean surviving the guard
    added to stop it."""
    r = _suite_repo(make_repo)
    helpers = r.root / "helpers"
    helpers.mkdir()
    (helpers / "conftest.py").write_text("import pytest\n")
    (helpers / "_util.py").write_text("X = 1\n")
    p = run_script("check_calls.py", str(helpers), "--target", "appx.summarize", cwd=r.root)
    assert p.returncode == 2, p.stdout + p.stderr
    assert "no tests" in p.stderr
    assert "0 test(s) that never reach the target" not in p.stdout


def test_a_suite_directory_with_no_python_is_refused_even_with_an_explicit_target(make_repo):
    """The backstop, and the reason it cannot be left to the existing no-targets arm: an
    explicit `--target` seeds the target map, so an empty directory sailed straight past it."""
    r = _suite_repo(make_repo)
    (r.root / "empty").mkdir()
    p = run_script("check_calls.py", str(r.root / "empty"), "--target", "appx.summarize", cwd=r.root)
    assert p.returncode == 2, p.stdout + p.stderr
    assert "no tests" in p.stderr
