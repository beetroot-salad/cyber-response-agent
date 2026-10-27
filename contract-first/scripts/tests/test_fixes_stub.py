"""Regression suite for the PR #674 check_stub fixes. Every invocation passes
`--python sys.executable`: the stub run must use a real interpreter with pytest."""
from __future__ import annotations

import sys
import textwrap

from conftest import run_script


def _spec_repo(make_repo):
    """A repo whose suite imports `appx.summarize` — a project-rooted module that does
    not exist (the not-yet-written target); `appx` is a namespace package."""
    r = make_repo()
    r.write("appx/helper.py", "def existing():\n    return 1\n")
    return r


def test_relative_suite_arg_from_nested_cwd_still_finds_the_suite(make_repo):
    # run() moves cwd for pytest, so a suite arg used as given would make
    # `cd tests && check_stub spec` hunt <rootdir>/spec and exit 2.
    r = _spec_repo(make_repo)
    r.write("tests/spec/test_spec.py", textwrap.dedent("""\
        from appx.summarize import summarize


        def test_real():
            assert summarize("a.txt") == "the summary"


        def test_vacuous():
            assert "secret" not in ""
    """))
    p = run_script("check_stub.py", "spec", "--python", sys.executable, cwd=r.root / "tests")
    assert p.returncode == 1, p.stdout + p.stderr
    assert "NULLSTUB-PASS" in p.stdout and "test_vacuous" in p.stdout
    assert "1 discriminating" in p.stdout


def test_teardown_error_does_not_demote_a_vacuous_pass(make_repo):
    # A fixture whose teardown breaks against the null stub (cleaning up a path the stub
    # never made) must not overwrite the call-phase PASS, or the one finding this check
    # exists for reads BROKEN.
    r = _spec_repo(make_repo)
    r.write("tests/spec/test_spec.py", textwrap.dedent("""\
        import pytest

        from appx.summarize import summarize


        @pytest.fixture
        def workdir():
            yield summarize("setup")
            raise RuntimeError("teardown cleans a path the stub never made")


        def test_vacuous(workdir):
            assert "secret" not in ""
    """))
    p = run_script(
        "check_stub.py", str(r.root / "tests/spec"), "--python", sys.executable, cwd=r.root,
    )
    assert p.returncode == 1, p.stdout + p.stderr
    assert "NULLSTUB-PASS" in p.stdout and "test_vacuous" in p.stdout
    assert "BROKEN" not in p.stdout


def test_existing_target_shadowing_the_stub_voids_the_run(make_repo):
    # `python -m pytest` puts the cwd ahead of PYTHONPATH, so a --target module that
    # EXISTS as a namespace-package module shadows the stub and the run would silently
    # classify real code. It must exit 2 with the shadowed message instead.
    r = _spec_repo(make_repo)
    r.write("appx/existing.py", "val = 3\n")
    r.write("tests/spec/test_spec.py", textwrap.dedent("""\
        from appx.existing import val


        def test_val():
            assert val == 3
    """))
    p = run_script(
        "check_stub.py", str(r.root / "tests/spec"), "--target", "appx.existing",
        "--python", sys.executable, cwd=r.root,
    )
    assert p.returncode == 2, p.stdout + p.stderr
    assert "shadowed" in p.stderr and "appx.existing" in p.stderr
    assert "NULLSTUB-PASS" not in p.stdout  # no silent classification of real code


def test_module_skipped_at_collection_is_a_finding_not_a_clean_exit(make_repo):
    # An importorskip'd module emits no per-test reports; the file must not vanish into
    # an exit 0 that certifies tests that never ran.
    r = _spec_repo(make_repo)
    r.write("tests/spec/test_real.py", textwrap.dedent("""\
        from appx.summarize import summarize


        def test_real():
            assert summarize("a.txt") == "the summary"
    """))
    r.write("tests/spec/test_skipped.py", textwrap.dedent("""\
        import pytest

        pytest.importorskip("no_such_module_pr674")

        from appx.summarize import summarize


        def test_never_runs():
            assert summarize("a.txt") == "the summary"
    """))
    p = run_script(
        "check_stub.py", str(r.root / "tests/spec"), "--python", sys.executable, cwd=r.root,
    )
    assert p.returncode == 1, p.stdout + p.stderr
    assert "SKIPPED" in p.stdout and "test_skipped" in p.stdout
    assert "1 discriminating" in p.stdout
