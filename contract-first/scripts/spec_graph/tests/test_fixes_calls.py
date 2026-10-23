"""Regression suite for the PR #674 check_calls fixes: explicit-target symbol imports,
module-level aliases, same-dir conftest fixtures, the greenfield-top-level floor note,
and cwd-independent root anchoring.

House style follows test_mechanical_checks: every test drives the real script via
subprocess and asserts on the exit code and the identity of the element named in the
finding, never exact wording. Exit contract: 0 clean, 1 found something, 2 could not
look.
"""
from __future__ import annotations

import textwrap

from test_mechanical_checks import run_script


def test_explicit_target_on_existing_module_sees_symbol_imports(make_repo):
    # An explicit `--target app.mod` names a module that EXISTS (the modify-existing
    # case), so the heuristic collected no symbols for it: a suite doing
    # `from app.mod import summarize` + summarize() was 100% falsely NO-CALL.
    r = make_repo()
    r.config(code_roots=["app"])
    r.write("app/mod.py", "def summarize(path):\n    return 'the summary'\n")
    r.write("tests/spec/test_spec.py", textwrap.dedent("""\
        from app.mod import summarize


        def test_returns_the_summary():
            assert summarize("a.txt") == "the summary"
    """))
    p = run_script("check_calls.py", str(r.root / "tests/spec"),
                   "--target", "app.mod", cwd=r.root)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "NO-CALL" not in p.stdout


def test_module_level_alias_of_the_target_reaches_the_fixed_point(make_repo):
    # A name bound to the target OUTSIDE any function (`functools.partial`, a plain
    # rebind) was invisible to the function-only harvest, so tests calling only the
    # alias were falsely NO-CALL. The genuinely vacuous test must STILL be flagged.
    r = make_repo()
    r.config(code_roots=["appx"])
    r.write("appx/helper.py", "def existing():\n    return 1\n")
    r.write("tests/spec/test_spec.py", textwrap.dedent("""\
        import functools

        from appx.summarize import summarize

        drive = functools.partial(summarize, strict=True)
        summ = summarize


        def test_via_partial():
            assert drive("a.txt") == "the summary"


        def test_via_plain_alias():
            assert summ("a.txt") == "the summary"


        def test_nothing_about_the_target():
            assert "secret" not in ""
    """))
    p = run_script("check_calls.py", str(r.root / "tests/spec"), cwd=r.root)
    assert p.returncode == 1
    assert "test_nothing_about_the_target" in p.stdout
    assert "test_via_partial" not in p.stdout
    assert "test_via_plain_alias" not in p.stdout


def test_conftest_fixture_that_reaches_the_target_covers_its_users(make_repo):
    # A test driving the target through a same-dir conftest fixture was falsely
    # NO-CALL: the fixed point was same-file only, but the fixture seam is exactly the
    # charge's "driving an object a call to the target returned". A test that touches
    # neither the target nor the fixture must STILL be flagged.
    r = make_repo()
    r.config(code_roots=["appx"])
    r.write("appx/helper.py", "def existing():\n    return 1\n")
    r.write("tests/spec/conftest.py", textwrap.dedent("""\
        import pytest

        from appx.engine import Engine


        @pytest.fixture
        def running_engine(tmp_path):
            return Engine(tmp_path)
    """))
    r.write("tests/spec/test_spec.py", textwrap.dedent("""\
        def test_drives_through_the_fixture(running_engine):
            assert running_engine.summarize("a.txt") == "the summary"


        def test_nothing_about_the_target():
            assert "secret" not in ""
    """))
    p = run_script("check_calls.py", str(r.root / "tests/spec"), cwd=r.root)
    assert p.returncode == 1
    assert "test_nothing_about_the_target" in p.stdout
    assert "test_drives_through_the_fixture" not in p.stdout


def test_greenfield_top_level_import_gets_a_floor_note(make_repo):
    # `from foo import parse` with no foo.py anywhere is indistinguishable from a
    # third-party import (single-segment blind spot), so the check must exit 2 (could
    # not look) AND name the ambiguous module in a floor note rather than claim that
    # every suite import resolves.
    r = make_repo()
    r.config(code_roots=[])
    r.write("tests/spec/test_spec.py", textwrap.dedent("""\
        from foo import parse


        def test_parses():
            assert parse("x") == "y"
    """))
    p = run_script("check_calls.py", str(r.root / "tests/spec"), cwd=r.root)
    assert p.returncode == 2
    assert "foo" in p.stderr and "--target" in p.stderr


def test_explicit_suite_path_is_judged_the_same_from_any_cwd(make_repo):
    # Root came from the git toplevel of the process cwd, so running against an
    # absolute suite path from an unrelated repo misclassified every import (nothing
    # project-rooted) and exited 2 with a false "every import resolves".
    r = make_repo()
    r.config(code_roots=["appx"])
    r.write("appx/helper.py", "def existing():\n    return 1\n")
    r.write("tests/spec/test_spec.py", textwrap.dedent("""\
        from appx.summarize import summarize


        def test_returns_the_summary():
            assert summarize("a.txt") == "the summary"


        def test_nothing_about_the_target():
            assert "secret" not in ""
    """))
    other = make_repo()  # an unrelated git repo the process happens to run from
    here = run_script("check_calls.py", str(r.root / "tests/spec"), cwd=r.root)
    away = run_script("check_calls.py", str(r.root / "tests/spec"), cwd=other.root)
    assert here.returncode == 1
    assert away.returncode == 1, away.stdout + away.stderr
    assert "test_nothing_about_the_target" in away.stdout
    assert "test_returns_the_summary" not in away.stdout
