"""Binding suite for #652 (a gate that cannot look must not report clean) and #654 (two
census-membership predicates that disagreed with their config).

Every test drives the REAL `check_actors.py` via subprocess against a throwaway git repo
(see conftest.Repo), and asserts on the observable payload — the exit code, and the identity
of the file named in the message — never on exact wording.

The exit-code contract under test:

    0  the census answered; no unmodelled driver reaches the change
    1  an unmodelled driver reaches the change (the gate LOOKED and found something)
    2  the census COULD NOT ANSWER (the gate could not look)

The 1-vs-2 split is the whole point of #652, so the blindness tests assert `== 2` rather than
"non-zero": collapsing the two would let a broken intermediate certify a graph clean, which is
the bug, and a `!= 0` assertion would pass against that collapse.
"""
from __future__ import annotations

import os
import subprocess

from conftest import DEFAULT_CHECK_ACTORS, run_script

BROKEN = "def (:\n"  # unparseable by ast.parse, in any Python
GRAPH = "schema_version: 1\ndemands: []\nactors: []\n"


def _run_bare(repo, *argv: str) -> subprocess.CompletedProcess[str]:
    """Drive check_actors with arbitrary argv — including NO graph path, which conftest's
    `Repo.run` cannot express (it always passes one) and which is exactly the no-artifacts case."""
    check = os.environ.get("CHECK_ACTORS_PATH", str(DEFAULT_CHECK_ACTORS))
    return run_script(check, *argv, cwd=repo.root, timeout=60)


def _chain_repo(make_repo, broken_rel: str | None):
    """run.py → mid.py → leaf.py, only leaf.py changed by the diff. `broken_rel`, if given, is
    made unparseable AT BASE and left untouched by the diff — #652's reproduction exactly. A file
    the diff itself touched would fire the rule for a second, independent reason, so breaking it
    at base is what isolates the reachability arm."""
    r = make_repo()
    r.config(code_roots=["app"], entrypoint_stems=("run",))
    r.write("app/run.py", "import app.mid\nif __name__ == '__main__':\n    pass\n")
    r.write("app/mid.py", "import app.leaf\n")
    r.write("app/leaf.py", "X = 1\n")
    r.write("app/orphan.py", "X = 1\n")  # in the census, imported by nobody
    r.graph(GRAPH)
    if broken_rel:
        r.write(broken_rel, BROKEN)
    base = r.commit("base")
    r.write("app/leaf.py", "X = 2\n")  # the ONLY change in the diff
    r.commit("change")
    return r, base


# ── #652 — a per-file census gap ─────────────────────────────────────────────
def test_unparseable_file_on_the_reach_path_refuses_to_certify(make_repo):
    """#652's exact repro. `run.py → mid.py → leaf.py`, leaf changed, mid unparseable at base.

    The reach `run → leaf` is real and unmodelled, but mid's parse failure denies the edges that
    would show it, so the gate is blind precisely where the answer lives. It must exit 2 — not 0
    (the old behaviour: 'clean' on a question it could not ask) and not 1 (which would claim it
    found a driver it did not). The positive control below proves the same repo exits 1 when mid
    parses, so this test cannot pass by the gate simply being broken."""
    r, base = _chain_repo(make_repo, "app/mid.py")
    out = r.run("spec_graph_x.yaml", base)
    assert out.returncode == 2, out.stdout + out.stderr
    assert "mid.py" in out.stderr
    # and it must NOT have printed a clean bill of health on stdout
    assert "0 unmodelled driver context(s)" not in out.stdout


def test_positive_control_same_repo_parses_and_reports_the_driver(make_repo):
    """The control for the test above: identical repo, mid.py intact. The reach resolves, the
    unmodelled `run` driver is found, exit 1. This is what the blind run was hiding."""
    r, base = _chain_repo(make_repo, None)
    out = r.run("spec_graph_x.yaml", base)
    assert out.returncode == 1, out.stdout + out.stderr
    assert "app/run.py" in out.stdout and "leaf" in out.stdout


def test_unparseable_file_nothing_reaches_only_warns(make_repo):
    """The precision half of the policy. `orphan.py` is in the census, unparseable at base, and
    the diff never touched it — no entrypoint reaches it, so no driver can be hiding behind it.
    It must WARN on stderr and change nothing about the exit code: the run still reports the real
    finding it found (exit 1). Reddening here would red every vendored fixture and every file
    using syntax newer than the runner, which is the cost that made #652 a decision at all."""
    r, base = _chain_repo(make_repo, "app/orphan.py")
    out = r.run("spec_graph_x.yaml", base)
    assert out.returncode == 1, out.stdout + out.stderr
    assert "orphan.py" in out.stderr and "WARN" in out.stderr
    assert "app/run.py" in out.stdout  # the gate still did its real job


def test_unparseable_file_the_diff_touched_refuses_to_certify(make_repo):
    """The second load-bearing arm: the blind file IS the change. We cannot read what the changed
    file imports, so we cannot say which drivers reach it — blind on the diff itself. Exit 2 even
    though nothing imports it, which is what separates this arm from the orphan case above."""
    r = make_repo()
    r.config(code_roots=["app"], entrypoint_stems=("run",))
    r.write("app/run.py", "if __name__ == '__main__':\n    pass\n")
    r.write("app/solo.py", "X = 1\n")
    r.graph(GRAPH)
    base = r.commit("base")
    r.write("app/solo.py", BROKEN)  # the diff breaks it
    r.commit("change")
    out = r.run("spec_graph_x.yaml", base)
    assert out.returncode == 2, out.stdout + out.stderr
    assert "solo.py" in out.stderr


# ── #652 — whole-gate blindness ──────────────────────────────────────────────
def test_no_artifacts_matched_is_not_clean(make_repo):
    """`artifacts` matching nothing checked zero graphs and printed '0 unmodelled ... over 0
    graph(s)', exit 0 — a pass earned by having no question to ask."""
    r = make_repo()
    r.config(code_roots=["app"], entrypoint_stems=("run",), artifacts="nope/spec_graph_*.yaml")
    r.write("app/run.py", "if __name__ == '__main__':\n    pass\n")
    r.commit("base")
    out = _run_bare(r, "--base", "main")
    assert out.returncode == 2, out.stdout + out.stderr
    assert "artifacts" in out.stderr


def test_empty_source_census_is_not_clean(make_repo):
    """codeRoots resolving to no .py files makes every reach question answer 'no' structurally."""
    r = make_repo()
    r.config(code_roots=["does_not_exist"], entrypoint_stems=("run",))
    r.write("app/run.py", "if __name__ == '__main__':\n    pass\n")
    r.graph(GRAPH)
    base = r.commit("base")
    out = r.run("spec_graph_x.yaml", base)
    assert out.returncode == 2, out.stdout + out.stderr
    assert "census" in out.stderr.lower()


# ── #654 — membership predicates ─────────────────────────────────────────────
def test_entrypoint_stems_honoured_for_underscore_prefixed_stem(make_repo):
    """#654.1: `_is_entrypoint` rejected `_`-prefixed stems BEFORE consulting the config, so
    `"entrypointStems": ["_harness"]` was silently ignored — a config option that did not do what
    it said. An explicit listing is the operator naming a runner the heuristics miss, so it must
    beat the heuristic."""
    r = make_repo()
    r.config(code_roots=["app"], entrypoint_stems=("_harness",))
    r.write("app/_harness.py", "import app.leaf\n")
    r.write("app/leaf.py", "X = 1\n")
    r.graph(GRAPH)
    base = r.commit("base")
    r.write("app/leaf.py", "X = 2\n")
    r.commit("change")
    out = r.run("spec_graph_x.yaml", base)
    assert out.returncode == 1, out.stdout + out.stderr
    assert "_harness" in out.stdout


def test_undeclared_underscore_stem_is_still_not_an_entrypoint(make_repo):
    """The boundary for the fix above: the `_` rule survives as the DEFAULT. A private module
    nobody declared is still not an execution context — the fix lets config win, it does not
    delete the heuristic."""
    r = make_repo()
    r.config(code_roots=["app"], entrypoint_stems=())
    r.write("app/_priv.py", "import app.leaf\nif __name__ == '__main__':\n    pass\n")
    r.write("app/leaf.py", "X = 1\n")
    r.graph(GRAPH)
    base = r.commit("base")
    r.write("app/leaf.py", "X = 2\n")
    r.commit("change")
    out = r.run("spec_graph_x.yaml", base)
    assert out.returncode == 0, out.stdout + out.stderr


def test_top_level_tests_dir_is_excluded_by_the_census_predicate(make_repo):
    """#654.2: `_changed_paths` filtered on `"/tests/" not in f` while `_config._kept` filters on
    a `tests` path COMPONENT, so top-level `tests/foo.py` survived one and was dropped by the
    other. The filter is gone; the census predicate is now the single definition of membership.

    Pins the behaviour that divergence would have broken: a changed top-level `tests/foo.py` is
    not a changed source module, so an entrypoint importing it raises no finding."""
    r = make_repo()
    r.config(code_roots=["."], entrypoint_stems=("run",))
    r.write("run.py", "import tests.foo\nif __name__ == '__main__':\n    pass\n")
    r.write("tests/foo.py", "X = 1\n")
    r.graph(GRAPH)
    base = r.commit("base")
    r.write("tests/foo.py", "X = 2\n")
    r.commit("change")
    out = r.run("spec_graph_x.yaml", base)
    assert out.returncode == 0, out.stdout + out.stderr
