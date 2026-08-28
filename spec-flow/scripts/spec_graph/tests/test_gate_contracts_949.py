"""#949 — three gate paths that measured something other than what they reported.

Same contract this family states everywhere and the same one #652 / #885 defended:

    0  the gate looked, and found nothing
    1  the gate looked, and found something
    2  the gate COULD NOT LOOK

Each test below drives the REAL script via subprocess against a throwaway repo, asserts the
exit code and the identity of the thing named, never the wording — the house style from
`test_gate_blindness_652_654` and `test_fixes_calls`. Every blindness assertion is `== 2`,
never `!= 0`: collapsing 1 and 2 is the bug in every one of these, so a truthiness assertion
would pass against the collapse it is supposed to catch. Each is paired with a positive
control proving the same fixture reaches a real answer when it can look.
"""
from __future__ import annotations

import json
import os
import sys
import textwrap

import pytest
from conftest import DEFAULT_CHECK_ACTORS, run_script

GRAPH = "schema_version: 1\ndemands: []\nactors: []\n"


# F-37a: check_actors must not answer over a base it could not resolve
def _diffable_repo(make_repo):
    r = make_repo()
    r.config(code_roots=["app"], entrypoint_stems=("run",))
    r.write("app/run.py", "import app.leaf\nif __name__ == '__main__':\n    pass\n")
    r.write("app/leaf.py", "X = 1\n")
    r.graph(GRAPH)
    base = r.commit("base")
    r.write("app/leaf.py", "X = 2\n")
    r.commit("change")
    return r, base


def test_an_unresolvable_base_is_a_could_not_look(make_repo):
    """`git diff` against a ref that names no commit here exits 128 with EMPTY stdout, and the
    changed set built from it is indistinguishable from "the diff touched nothing" — so the
    import-reach arm silently stopped answering. Measured on the real repo before the fix:
    `--base main` reported 286 findings and a nonexistent base reported 42, the same as a
    near-empty diff, with nothing said about the ref."""
    r, _ = _diffable_repo(make_repo)
    out = r.run("spec_graph_x.yaml", "does-not-exist-ref")
    assert out.returncode == 2, out.stdout + out.stderr
    assert "does-not-exist-ref" in out.stderr, out.stderr
    assert "unmodelled driver context(s)" not in out.stdout


def test_positive_control_a_real_base_still_answers(make_repo):
    """The control: the same fixture, a base that resolves. The gate reaches a verdict, so the
    test above cannot pass merely by check_actors being broken."""
    r, base = _diffable_repo(make_repo)
    out = r.run("spec_graph_x.yaml", base)
    assert out.returncode in (0, 1), out.stdout + out.stderr
    assert "unmodelled driver context(s)" in out.stdout


def _run_bare(repo, *argv):
    """check_actors with arbitrary argv — `Repo.run` always passes `--base`, and the whole
    point of the test below is the run that does not.

    `$CHECK_ACTORS_PATH` is honoured, the same two lines `test_gate_blindness_652_654._run_bare`
    uses: conftest documents that override as the null-stub discrimination seam, so a copy that
    hardcodes the real script is structurally exempt from the gate every other test here is
    measured by."""
    check = os.environ.get("CHECK_ACTORS_PATH", str(DEFAULT_CHECK_ACTORS))
    return run_script(check, *argv, cwd=repo.root, timeout=60)


def test_the_default_base_comes_from_the_profile_not_a_hardcoded_main(make_repo):
    """The preflight above turns a wrong default base into a hard refusal rather than a quiet
    empty diff, so the default has to be the branch the project declares.

    `conventions.defaultBranch` is the key the ship skill already reads, and spec-flow ships as
    a plugin to repos we do not control — one on `master` would otherwise owe an explicit
    `--base` on every invocation, where before the preflight it merely got a quiet wrong
    answer. Trading one failure mode for another is not the fix.

    Asserted POSITIVELY — the census reached a verdict — and not as `returncode != 2`. A crash
    in `main` exits 1 with an empty stderr, which satisfies both a `!= 2` and a substring
    absence; this file's own docstring forbids exactly that shape, and the assertion below is
    the one that fails when the config path is broken or stubbed out."""
    r, _ = _diffable_repo(make_repo)
    r._git("branch", "-M", "master")
    profile = json.loads((r.root / ".claude/spec-flow.json").read_text())
    profile["conventions"] = {"defaultBranch": "master"}
    r.write(".claude/spec-flow.json", json.dumps(profile))
    r.commit("declare the branch")
    out = _run_bare(r, "spec_graph_x.yaml")
    assert out.returncode in (0, 1), out.stdout + out.stderr
    assert "unmodelled driver context(s) over 1 graph(s) (base=master)" in out.stdout, out.stdout


def test_the_default_base_is_refused_when_the_profile_does_not_declare_it(make_repo):
    """The discriminating twin: the SAME fixture with no `conventions.defaultBranch`. The default
    falls back to `main`, which this repo (renamed to `master`) does not have, so the preflight
    refuses. Without this the test above passes on a build that ignores the profile entirely and
    happens to be handed a repo where `main` also resolves."""
    r, _ = _diffable_repo(make_repo)
    r._git("branch", "-M", "master")
    out = _run_bare(r, "spec_graph_x.yaml")
    assert out.returncode == 2, out.stdout + out.stderr
    assert "does not resolve to a commit" in out.stderr, out.stderr


# F-37b: check_binds joins the rest of the family on an empty corpus
def test_check_binds_reports_an_empty_corpus_as_could_not_look(make_repo, tmp_path):
    """`check_claims`, `check_lint` and `check_gate` all return 2 on this identical branch, and
    check_binds' own unreadable-graph arm returns 2 — it was the one member reporting "there
    was nothing to read" as a clean run."""
    r = make_repo()
    r.config(code_roots=["app"], artifacts="**/no_such_graph_*.yaml")
    r.write("app/mod.py", "X = 1\n")
    r.commit("base")
    p = run_script("check_binds.py", cwd=r.root)
    assert p.returncode == 2, p.stdout + p.stderr
    assert "no spec_graph_*.yaml found" in p.stderr


# F-38: the suite is the one the graph NAMES, not the dir it sits in
def _graph_and_suite(make_repo):
    """A graph in `specs/` whose `tests:` names a suite somewhere else entirely — the layout
    the corpus actually has, and the one `p.parent` gets wrong."""
    r = make_repo()
    r.config(code_roots=["app"])
    r.write("app/mod.py", "def summarize(path):\n    return 'the summary'\n")
    r.write("specs/spec_graph_x.yaml", "schema_version: 1\ntests: suite\ndemands: []\n")
    r.write("suite/test_spec.py", textwrap.dedent("""\
        from app.mod import summarize


        def test_touches_the_target():
            assert summarize("a.txt") == "the summary"


        def test_never_touches_the_target():
            assert 1 == 1
    """))
    r.commit("base")
    return r


def _greenfield_graph_and_suite(make_repo):
    """As above, but the suite imports a module that does NOT exist yet — the spec-time shape,
    where the import heuristic can name the target on its own."""
    r = make_repo()
    r.config(code_roots=["app"])
    r.write("app/existing.py", "X = 1\n")
    r.write("specs/spec_graph_x.yaml", "schema_version: 1\ntests: suite\ndemands: []\n")
    r.write("suite/test_spec.py", textwrap.dedent("""\
        from app.newmod import summarize


        def test_drives_the_target():
            assert summarize("a.txt") == "the summary"
    """))
    r.commit("base")
    return r


def test_check_calls_follows_the_graphs_tests_field(make_repo):
    """Handed a GRAPH — the form its own usage line advertises — check_calls took the graph's
    own directory as the suite. That directory holds no Python, so with `--target` given it
    printed "0 test(s) that never reach the target" and exited 0 over a suite it never opened.
    It must find the vacuous test in the suite the graph names."""
    r = _graph_and_suite(make_repo)
    p = run_script("check_calls.py", str(r.root / "specs/spec_graph_x.yaml"),
                   "--target", "app.mod", cwd=r.root)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "test_never_touches_the_target" in p.stdout
    assert "test_touches_the_target:" not in p.stdout


def test_check_stub_follows_the_graphs_tests_field(make_repo):
    """check_stub carried the identical two lines and now shares the same resolution helper.

    Driven greenfield — the suite imports `app.newmod`, which does not exist — so the import
    heuristic identifies a target with no `--target` flag to seed it. Over the suite the graph
    names, that is a real stub pass. Over the graph's own directory it is nothing at all, and
    the old code said so while naming the wrong directory: `no target identified for
    .../specs — every suite import resolves`, exit 2. That message is the discriminator."""
    r = _greenfield_graph_and_suite(make_repo)
    p = run_script("check_stub.py", str(r.root / "specs/spec_graph_x.yaml"),
                   "--python", sys.executable, cwd=r.root)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "app.newmod" in p.stdout, p.stdout
    assert "no target identified" not in p.stderr, p.stderr


def test_a_directory_of_helpers_with_no_tests_is_refused(make_repo):
    """The guard asks whether pytest would COLLECT anything, not whether the directory holds
    `.py`. A suite of only `conftest.py` and helpers passes a bare-Python test while collecting
    nothing, and the run then prints its clean line — `0 test(s) that never reach the target`,
    exit 0 — over a suite with no tests in it. That is the #949 false clean surviving the guard
    added to stop it."""
    r = _graph_and_suite(make_repo)
    helpers = r.root / "helpers"
    helpers.mkdir()
    (helpers / "conftest.py").write_text("import pytest\n")
    (helpers / "_util.py").write_text("X = 1\n")
    p = run_script("check_calls.py", str(helpers), "--target", "app.mod", cwd=r.root)
    assert p.returncode == 2, p.stdout + p.stderr
    assert "no tests" in p.stderr
    assert "0 test(s) that never reach the target" not in p.stdout


def test_a_suite_directory_with_no_python_is_refused_even_with_an_explicit_target(make_repo):
    """The backstop, and the reason it cannot be left to the existing no-targets arm: an
    explicit `--target` seeds the target map, so an empty directory sailed straight past it."""
    r = _graph_and_suite(make_repo)
    (r.root / "empty").mkdir()
    p = run_script("check_calls.py", str(r.root / "empty"), "--target", "app.mod", cwd=r.root)
    assert p.returncode == 2, p.stdout + p.stderr
    assert "no tests" in p.stderr


# ── F-38b: the recorded-pass allow-list follows the graphs that NAME the suite ──
def _recorded_pass_repo(make_repo):
    """TWO graphs in `specs/`, both naming the one `suite/`, each recording one of its vacuous
    tests. Neither is a sibling of the suite, which is the whole point: the sibling glob that
    used to be the only source finds nothing here."""
    r = make_repo()
    r.config(code_roots=["app"])
    r.write("app/existing.py", "X = 1\n")
    for graph, recorded in (("a", "test_recorded_by_a"), ("b", "test_recorded_by_b")):
        r.write(f"specs/spec_graph_{graph}.yaml",
                "schema_version: 1\ntests: suite\ndemands: []\nhandoff:\n"
                f'  nullstub_passes:\n    - "{recorded} — deliberate"\n')
    r.write("suite/test_spec.py", textwrap.dedent("""\
        from app.newmod import summarize


        def test_recorded_by_a():
            assert True


        def test_recorded_by_b():
            assert True


        def test_really_drives_it():
            assert summarize("a.txt") == "the summary"
    """))
    r.commit("base")
    return r


@pytest.mark.parametrize("arg", ["specs/spec_graph_a.yaml", "suite", None],
                         ids=["graph", "suite-dir", "no-arg"])
def test_recorded_passes_are_read_from_every_graph_that_names_the_suite(make_repo, arg):
    """pytest is handed the whole SUITE, so the allow-list has to cover every graph that names
    it — including, for the graph form, the SIBLING graphs the argument does not mention.

    All three invocation forms must agree: `spec-graph nullstub <suite-dir>` is the one
    write-tests actually emits, and a directory carries no graph identity of its own. Reading one
    graph's block (or none) re-reports a consciously recorded pass as a NULLSTUB-PASS finding —
    advising the author to record it in the very block that already records it."""
    r = _recorded_pass_repo(make_repo)
    argv = [str(r.root / arg)] if arg else []
    p = run_script("check_stub.py", *argv, "--python", sys.executable,
                   "--target", "app.newmod", cwd=r.root)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "NULLSTUB-PASS" not in p.stdout, p.stdout


def test_an_unrecorded_pass_is_still_a_finding(make_repo):
    """The positive control: the allow-list suppresses precisely what it lists, and a third
    vacuous test nobody recorded is still reported. Without this the test above passes on a
    check_stub that reports nothing at all."""
    r = _recorded_pass_repo(make_repo)
    r.write("suite/test_extra.py", "def test_nobody_recorded_me():\n    assert True\n")
    r.commit("an unrecorded vacuous test")
    p = run_script("check_stub.py", str(r.root / "suite"), "--python", sys.executable,
                   "--target", "app.newmod", cwd=r.root)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "test_nobody_recorded_me" in p.stdout, p.stdout
    assert "test_recorded_by_a" not in p.stdout, p.stdout
    assert "test_recorded_by_b" not in p.stdout, p.stdout


# F-39: the alphabet rule reaches the claims that enumerate
CENSUS_CLAIM = textwrap.dedent("""\
    schema_version: 1
    demands: []
    claims:
      - id: C1
        kind: census
        probe_kind: search
        verdict: holds
        claim: "every adapter under scripts/ declares a health-check verb"
        probe: "git ls-files scripts/ | grep adapter, then read each"
        observed: "seven adapters, all declaring health-check"
    """)

#: Nested at the claim's own key depth (4 spaces) — written as a literal rather than a
#: dedented block, because dedent would strip it back to the document root and the claim
#: would still be missing its alphabet. That mistake made this control pass vacuously once.
ALPHABET_BLOCK = (
    "    alphabet:\n"
    '      ascii: "all seven names are ascii"\n'
    '      non-ascii: "none present in this tree'"'"'s seven names"\n'
    '      space: "none present; the listing was taken with -z"\n'
    '      cwd: "run from the repo root; paths are repo-relative"\n'
)


def test_a_census_claim_that_enumerates_owes_an_alphabet(make_repo):
    """The rule was gated on `probe_kind == "executed"`, and `_REQUIRED["census"] == {"search"}`
    makes a census claim closing on anything else a finding in its own right — so no gate-clean
    graph could ever present one here and the rule was unfireable on exactly the claims it was
    written for. Nine committed census claims enumerate a tree and record no alphabet."""
    r = make_repo()
    r.config(code_roots=["app"])
    r.write("app/mod.py", "X = 1\n")
    r.write("spec_graph_x.yaml", CENSUS_CLAIM)
    r.commit("base")
    p = run_script("check_claims.py", str(r.root / "spec_graph_x.yaml"), cwd=r.root)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "C1" in p.stdout and "alphabet" in p.stdout


def test_the_same_claim_with_an_alphabet_passes(make_repo):
    """The positive control — the rule is satisfiable, not just loud. A sentence per class is
    the whole mechanism, and an out-of-scope class closes by saying so."""
    r = make_repo()
    r.config(code_roots=["app"])
    r.write("app/mod.py", "X = 1\n")
    r.write("spec_graph_x.yaml", CENSUS_CLAIM + ALPHABET_BLOCK)
    r.commit("base")
    p = run_script("check_claims.py", str(r.root / "spec_graph_x.yaml"), cwd=r.root)
    # The exit code, not just the absent word: a crash prints nothing to stdout and would
    # satisfy the substring assertion on its own — the same vacuous pass the ALPHABET_BLOCK
    # indentation note above records having already happened here once.
    assert p.returncode == 0, p.stdout + p.stderr
    assert "alphabet" not in p.stdout, p.stdout
