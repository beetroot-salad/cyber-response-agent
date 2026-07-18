"""Binding suite for issue #643 — check_actors' import-arm fix.

Each test drives the REAL entry point (`check_actors.py` via subprocess, see conftest.Repo) against
a throwaway git repo with a NAMESPACE-PACKAGE source tree (no `__init__.py`). Assertions are on the
OBSERVABLE payload — the process exit code and the identity (entrypoint rel-path + reached changed
module stem) carried in the finding text — never the literal `[...]` bracket rendering, which the fix
legitimately enlarges. Every negative test drives its positive control in the same test, so the whole
suite fails against a no-op stub.

This spec is written BEFORE the fix. Fix-demand tests are RED against the current (buggy) worktree
code and turn GREEN once `_imported_stems`/the import arm resolves `from pkg import sub`, relative,
multi-name and parenthesized forms to files on disk and follows imports transitively (PATH-granular,
codeRoots-bounded). Preserved-behavior tests are GREEN now.
"""
from __future__ import annotations

import pytest

# A graph that models nothing (no entrypoint stem appears): nothing is suppressed.
UNMODELLED_GRAPH = "schema_version: 1\ndemands: []\nactors: []\n"


def _graph_modelling(*names: str) -> str:
    body = "".join(f"  - id: {n}\n" for n in names)
    return "schema_version: 1\nactors:\n" + body


# ── #0 output/exit contract ──────────────────────────────────────────────────
def test_findings_list_and_exit_code_contract(make_repo):
    """main() exits 1 when an unmodelled driver reaches the change (finding printed) and 0 when
    none does — the findings-list / exit-code contract."""
    # Firing: a fully-qualified import of a changed module (works today) → exit 1 + finding.
    firing = make_repo()
    firing.config(code_roots=["app"], entrypoint_stems=("run",))
    firing.write("app/run.py", "import app.pkg.alpha\nif __name__ == '__main__':\n    pass\n")
    firing.write("app/pkg/alpha.py", "X = 1\n")
    firing.graph(UNMODELLED_GRAPH)
    base = firing.commit("base")
    firing.write("app/pkg/alpha.py", "X = 2\n")
    firing.commit("change")
    r = firing.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert "UNMODELLED" in r.stdout
    assert "app/run.py" in r.stdout and "alpha" in r.stdout

    # Clean: nothing an entrypoint reaches changed → exit 0, no findings.
    clean = make_repo()
    clean.config(code_roots=["app"], entrypoint_stems=("run",))
    clean.write("app/run.py", "import app.pkg.alpha\nif __name__ == '__main__':\n    pass\n")
    clean.write("app/pkg/alpha.py", "X = 1\n")
    clean.write("app/pkg/untouched.py", "Y = 1\n")
    clean.graph(UNMODELLED_GRAPH)
    cbase = clean.commit("base")
    clean.write("app/pkg/untouched.py", "Y = 2\n")  # not reached by run.py
    clean.commit("change")
    rc = clean.run("spec_graph_x.yaml", cbase)
    assert rc.returncode == 0
    assert "UNMODELLED" not in rc.stdout


# ── O1 direct named-import resolution ────────────────────────────────────────
def test_from_pkg_import_changed_submodule_is_flagged(make_repo):
    """`from pkg import changed_submodule` flags the entrypoint: exit 1, finding names the
    entrypoint and the changed submodule."""
    repo = make_repo()
    repo.config(code_roots=["app"], entrypoint_stems=("run",))
    repo.write("app/run.py", "from app.pkg import beta\nif __name__ == '__main__':\n    pass\n")
    repo.write("app/pkg/beta.py", "X = 1\n")
    repo.graph(UNMODELLED_GRAPH)
    base = repo.commit("base")
    repo.write("app/pkg/beta.py", "X = 2\n")
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert "app/run.py" in r.stdout
    assert "beta" in r.stdout


def test_fully_qualified_import_of_changed_module_is_flagged(make_repo):
    """`import a.b.changed` flags the entrypoint — the positive baseline control (works today) the
    stdlib/symbol negatives lean on."""
    repo = make_repo()
    repo.config(code_roots=["app"], entrypoint_stems=("run",))
    repo.write("app/run.py", "import app.pkg.gamma\nif __name__ == '__main__':\n    pass\n")
    repo.write("app/pkg/gamma.py", "X = 1\n")
    repo.graph(UNMODELLED_GRAPH)
    base = repo.commit("base")
    repo.write("app/pkg/gamma.py", "X = 2\n")
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert "app/run.py" in r.stdout
    assert "gamma" in r.stdout


# ── O3 relative & multi-name forms ───────────────────────────────────────────
@pytest.mark.parametrize(
    "entry_rel, entry_src, changed_rel",
    [
        # single-dot: sibling of the entrypoint's own package
        ("app/pkg/run_single.py", "from . import sib1\nif __name__ == '__main__':\n    pass\n",
         "app/pkg/sib1.py"),
        # multi-dot: `from .. import mod` resolves up one package
        ("app/pkg/sub/run_multi.py", "from .. import sib2\nif __name__ == '__main__':\n    pass\n",
         "app/pkg/sib2.py"),
    ],
)
def test_relative_import_to_changed_module_is_flagged(make_repo, entry_rel, entry_src, changed_rel):
    """A relative import (`from . import mod`, `from .. import mod`) of a changed module flags the
    entrypoint."""
    repo = make_repo()
    repo.config(code_roots=["app"])
    repo.write(entry_rel, entry_src)
    repo.write(changed_rel, "X = 1\n")
    repo.graph(UNMODELLED_GRAPH)
    base = repo.commit("base")
    repo.write(changed_rel, "X = 2\n")
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert entry_rel in r.stdout
    changed_stem = changed_rel.rsplit("/", 1)[-1][:-3]
    assert changed_stem in r.stdout


@pytest.mark.parametrize("change_first", [True, False])
def test_multiname_import_credits_each_changed_name(make_repo, change_first):
    """`from a import b, c` credits each imported name: both flagged when both change, and the
    trailing name alone flagged when only it changes (never dropped)."""
    repo = make_repo()
    repo.config(code_roots=["app"], entrypoint_stems=("run",))
    repo.write(
        "app/run.py", "from app.pkg import mfirst, msecond\nif __name__ == '__main__':\n    pass\n"
    )
    repo.write("app/pkg/mfirst.py", "X = 1\n")
    repo.write("app/pkg/msecond.py", "X = 1\n")
    repo.graph(UNMODELLED_GRAPH)
    base = repo.commit("base")
    if change_first:
        repo.write("app/pkg/mfirst.py", "X = 2\n")
    repo.write("app/pkg/msecond.py", "X = 2\n")  # msecond (the trailing name) always changes
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert "msecond" in r.stdout  # the trailing name is always credited
    if change_first:
        assert "mfirst" in r.stdout
    else:
        assert "mfirst" not in r.stdout  # unchanged → not credited (arm stays changed-gated)


def test_parenthesized_multiline_import_is_flagged(make_repo):
    """A parenthesized multi-line import whose continuation-line name is a changed module flags the
    entrypoint."""
    repo = make_repo()
    repo.config(code_roots=["app"], entrypoint_stems=("run",))
    repo.write(
        "app/run.py",
        "from app.pkg import (\n    pfirst,\n    psecond,\n)\nif __name__ == '__main__':\n    pass\n",
    )
    repo.write("app/pkg/pfirst.py", "X = 1\n")
    repo.write("app/pkg/psecond.py", "X = 1\n")
    repo.graph(UNMODELLED_GRAPH)
    base = repo.commit("base")
    repo.write("app/pkg/psecond.py", "X = 2\n")  # a continuation-line name
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert "app/run.py" in r.stdout
    assert "psecond" in r.stdout


# ── O2 transitive ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("depth", [2, 3])
def test_transitive_reach_to_changed_module_is_flagged(make_repo, depth):
    """An entrypoint that reaches a changed module only transitively (run→driver→compaction, and
    deeper) is flagged."""
    repo = make_repo()
    repo.config(code_roots=["app"], entrypoint_stems=("run",))
    repo.write("app/run.py", "from app.runtime import driver\nif __name__ == '__main__':\n    pass\n")
    if depth == 2:
        repo.write("app/runtime/driver.py", "from . import compaction\n")
        leaf = "app/runtime/compaction.py"
    else:
        repo.write("app/runtime/driver.py", "from . import midhop\n")
        repo.write("app/runtime/midhop.py", "from . import compaction\n")
        leaf = "app/runtime/compaction.py"
    repo.write(leaf, "X = 1\n")
    repo.graph(UNMODELLED_GRAPH)
    base = repo.commit("base")
    repo.write(leaf, "X = 2\n")
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert "app/run.py" in r.stdout
    assert "compaction" in r.stdout


def test_transitive_finding_names_the_reached_changed_module(make_repo):
    """The transitive finding names the reached changed LEAF (compaction), not the intermediate
    (driver)."""
    repo = make_repo()
    repo.config(code_roots=["app"], entrypoint_stems=("run",))
    repo.write("app/run.py", "from app.runtime import driver\nif __name__ == '__main__':\n    pass\n")
    repo.write("app/runtime/driver.py", "from . import compaction\n")
    repo.write("app/runtime/compaction.py", "X = 1\n")
    repo.graph(UNMODELLED_GRAPH)
    base = repo.commit("base")
    repo.write("app/runtime/compaction.py", "X = 2\n")  # only the leaf changes
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert "app/run.py" in r.stdout
    assert "compaction" in r.stdout  # the reached changed leaf is named
    assert "driver" not in r.stdout  # the intermediate is NOT named — only the reached leaf


def test_transitive_changed_sibling_fires_unchanged_stays_silent(make_repo):
    """When an intermediate imports a changed sibling and an unchanged sibling at the same depth,
    the changed one fires and the unchanged stays silent (the import arm stays changed-gated)."""
    repo = make_repo()
    repo.config(code_roots=["app"], entrypoint_stems=("run",))
    repo.write("app/run.py", "from app.runtime import mid\nif __name__ == '__main__':\n    pass\n")
    repo.write("app/runtime/mid.py", "from . import changedsib\nfrom . import unchangedsib\n")
    repo.write("app/runtime/changedsib.py", "X = 1\n")
    repo.write("app/runtime/unchangedsib.py", "Y = 1\n")
    repo.graph(UNMODELLED_GRAPH)
    base = repo.commit("base")
    repo.write("app/runtime/changedsib.py", "X = 2\n")  # only this sibling changes
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert "changedsib" in r.stdout
    assert "unchangedsib" not in r.stdout


# ── N5 termination ───────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "topology",
    ["two_node", "three_ring", "self_loop"],
)
def test_import_cycle_terminates_and_still_flags(make_repo, topology):
    """An import cycle (2-node ↔, 3-node ring, self-loop) terminates (no hang) and still flags the
    changed module on the path."""
    repo = make_repo()
    repo.config(code_roots=["app"], entrypoint_stems=("run",))
    repo.write("app/run.py", "from app.pkg import cyca\nif __name__ == '__main__':\n    pass\n")
    if topology == "two_node":
        repo.write("app/pkg/cyca.py", "from . import cycb\n")
        repo.write("app/pkg/cycb.py", "from . import cyca\nZ = 1\n")
        changed = "app/pkg/cycb.py"
    elif topology == "three_ring":
        repo.write("app/pkg/cyca.py", "from . import cycb\n")
        repo.write("app/pkg/cycb.py", "from . import cycc\n")
        repo.write("app/pkg/cycc.py", "from . import cyca\nZ = 1\n")
        changed = "app/pkg/cycc.py"
    else:  # self_loop
        repo.write("app/pkg/cyca.py", "from . import cyca\nZ = 1\n")
        changed = "app/pkg/cyca.py"
    repo.graph(UNMODELLED_GRAPH)
    base = repo.commit("base")
    txt = (repo.root / changed).read_text()
    repo.write(changed, txt + "Z2 = 2\n")
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)  # conftest timeout=60 catches a non-terminating walk
    assert r.returncode == 1
    changed_stem = changed.rsplit("/", 1)[-1][:-3]
    assert changed_stem in r.stdout


# ── N3 false-positive freedom (negatives + paired controls) ──────────────────
def test_from_pkg_import_symbol_with_no_file_invents_no_driver(make_repo):
    """`from pkg import symbol` where no symbol.py exists invents no driver; a real changed
    submodule in the same shape does fire (control)."""
    # Negative: `helper` is a function, no app/pkg/helper.py; nothing it names changed → no finding.
    neg = make_repo()
    neg.config(code_roots=["app"], entrypoint_stems=("run",))
    neg.write("app/run.py", "from app.pkg import helper\nif __name__ == '__main__':\n    pass\n")
    neg.write("app/pkg/api.py", "def helper():\n    return 1\n")  # helper lives here, not helper.py
    neg.write("app/pkg/unrelated.py", "Q = 1\n")
    neg.graph(UNMODELLED_GRAPH)
    nbase = neg.commit("base")
    neg.write("app/pkg/unrelated.py", "Q = 2\n")  # a changed module the entrypoint never names
    neg.commit("change")
    rn = neg.run("spec_graph_x.yaml", nbase)
    assert rn.returncode == 0  # no phantom driver invented for the symbol
    assert "app/run.py" not in rn.stdout

    # Control: same `from pkg import X` shape but X is a real changed submodule → fires.
    ctl = make_repo()
    ctl.config(code_roots=["app"], entrypoint_stems=("run",))
    ctl.write("app/run.py", "from app.pkg import realsub\nif __name__ == '__main__':\n    pass\n")
    ctl.write("app/pkg/realsub.py", "X = 1\n")
    ctl.graph(UNMODELLED_GRAPH)
    cbase = ctl.commit("base")
    ctl.write("app/pkg/realsub.py", "X = 2\n")
    ctl.commit("change")
    rc = ctl.run("spec_graph_x.yaml", cbase)
    assert rc.returncode == 1
    assert "realsub" in rc.stdout


def test_stdlib_or_thirdparty_import_is_never_a_driver(make_repo):
    """A stdlib / third-party import is never a driver; a real changed project import in the same
    fixture does fire (control)."""
    repo = make_repo()
    repo.config(code_roots=["app"], entrypoint_stems=("run", "loop"))
    # stdlib-only driver: imports os/sys, no project reach → must NOT be flagged.
    repo.write("app/loop.py", "import os\nimport sys\nif __name__ == '__main__':\n    pass\n")
    # control driver: a real changed project import (fully-qualified, works today) → fires.
    repo.write("app/run.py", "import app.pkg.delta\nif __name__ == '__main__':\n    pass\n")
    repo.write("app/pkg/delta.py", "X = 1\n")
    repo.graph(UNMODELLED_GRAPH)
    base = repo.commit("base")
    repo.write("app/pkg/delta.py", "X = 2\n")
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert "app/run.py" in r.stdout and "delta" in r.stdout
    assert "app/loop.py" not in r.stdout  # the stdlib-only driver produced no finding


def test_pkg_head_stem_collision_yields_no_false_reach(make_repo):
    """`from a.runtime import driver` with an unrelated top-level runtime.py changed yields no
    false reach; driver.py changed does fire (control)."""
    # Negative: `from app.runtime import driver` — HEAD credits the package HEAD `runtime` (a1),
    # which collides with an unrelated changed app/other/runtime.py and false-fires. driver.py is
    # UNCHANGED; the path-granular fix resolves to app/runtime/driver.py → no reach.
    neg = make_repo()
    neg.config(code_roots=["app"], entrypoint_stems=("run",))
    neg.write("app/run.py", "from app.runtime import driver\nif __name__ == '__main__':\n    pass\n")
    neg.write("app/runtime/driver.py", "X = 1\n")
    neg.write("app/other/runtime.py", "R = 1\n")
    neg.graph(UNMODELLED_GRAPH)
    nbase = neg.commit("base")
    neg.write("app/other/runtime.py", "R = 2\n")  # unrelated same-stem (package-head) module changes
    neg.commit("change")
    rn = neg.run("spec_graph_x.yaml", nbase)
    assert rn.returncode == 0  # driver.py unchanged, other/runtime.py not imported → no reach

    # Control: the imported driver.py itself changes → fires.
    ctl = make_repo()
    ctl.config(code_roots=["app"], entrypoint_stems=("run",))
    ctl.write("app/run.py", "from app.runtime import driver\nif __name__ == '__main__':\n    pass\n")
    ctl.write("app/runtime/driver.py", "X = 1\n")
    ctl.graph(UNMODELLED_GRAPH)
    cbase = ctl.commit("base")
    ctl.write("app/runtime/driver.py", "X = 2\n")
    ctl.commit("change")
    rc = ctl.run("spec_graph_x.yaml", cbase)
    assert rc.returncode == 1
    assert "driver" in rc.stdout


# ── N4 suppression keyed on the entrypoint ───────────────────────────────────
def test_modelled_driver_stays_suppressed_after_fix(make_repo):
    """A modelled entrypoint (its stem, or its contextAlias, in the graph) stays suppressed even
    though it reaches a changed module; an unmodelled entrypoint fires."""
    repo = make_repo()
    repo.config(
        code_roots=["app"],
        entrypoint_stems=("run", "loop", "svc"),
        context_aliases={"svc": "run_investigation"},
    )
    # modelled by stem: `run` reaches a changed module (fully-qualified, works today) but is in graph.
    repo.write("app/run.py", "import app.pkg.rmod\nif __name__ == '__main__':\n    pass\n")
    repo.write("app/pkg/rmod.py", "X = 1\n")
    # modelled only via contextAlias: `svc`→run_investigation, alias appears in graph, stem does not.
    repo.write("app/svc.py", "import app.pkg.smod\nif __name__ == '__main__':\n    pass\n")
    repo.write("app/pkg/smod.py", "X = 1\n")
    # unmodelled control: `loop` reaches a changed module, absent from graph → fires.
    repo.write("app/loop.py", "import app.pkg.lmod\nif __name__ == '__main__':\n    pass\n")
    repo.write("app/pkg/lmod.py", "X = 1\n")
    repo.graph(_graph_modelling("run", "run_investigation"))
    base = repo.commit("base")
    for m in ("rmod", "smod", "lmod"):
        repo.write(f"app/pkg/{m}.py", "X = 2\n")
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert "app/loop.py" in r.stdout and "lmod" in r.stdout  # unmodelled fires
    assert "app/run.py" not in r.stdout  # modelled by stem → suppressed
    assert "app/svc.py" not in r.stdout  # modelled by contextAlias → suppressed


def test_suppression_keyed_on_entrypoint_not_reached_module(make_repo):
    """Suppression is keyed on the entrypoint stem, not the reached module: an unmodelled entrypoint
    fires even when the reached changed module's stem appears in the graph."""
    repo = make_repo()
    repo.config(code_roots=["app"], entrypoint_stems=("loop",))
    # `loop` is NOT modelled; the reached module `reachedmod` IS named in the graph. The reached
    # module's presence must not suppress the entrypoint.
    repo.write("app/loop.py", "from app.pkg import reachedmod\nif __name__ == '__main__':\n    pass\n")
    repo.write("app/pkg/reachedmod.py", "X = 1\n")
    repo.graph(_graph_modelling("reachedmod"))  # graph names the REACHED module, not the entrypoint
    base = repo.commit("base")
    repo.write("app/pkg/reachedmod.py", "X = 2\n")
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert "app/loop.py" in r.stdout  # fires despite reachedmod being modelled
    assert "reachedmod" in r.stdout


# ── N1 subprocess arm survives ───────────────────────────────────────────────
def test_subprocess_arm_still_fires_ungated_by_changed(make_repo):
    """The subprocess re-exec arm still fires, with its own re-execute wording, ungated by the
    changed set."""
    repo = make_repo()
    repo.config(code_roots=["app"], entrypoint_stems=("run",))
    repo.write(
        "app/run.py",
        "import subprocess, sys\n"
        "subprocess.run([sys.executable, 'app/pkg/subtarget.py'])\n"
        "if __name__ == '__main__':\n    pass\n",
    )
    repo.write("app/pkg/subtarget.py", "X = 1\n")  # a project module, never changed
    repo.write("app/pkg/noise.py", "N = 1\n")
    repo.graph(UNMODELLED_GRAPH)
    base = repo.commit("base")
    repo.write("app/pkg/noise.py", "N = 2\n")  # an unrelated change; run.py imports nothing changed
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert "app/run.py" in r.stdout
    assert "subtarget" in r.stdout
    assert "subprocess" in r.stdout  # the re-exec wording, not the import wording


# ── clean-exit and /tests/-exclusion boundaries ──────────────────────────────
def test_diff_with_no_in_scope_reach_exits_zero(make_repo):
    """A diff no in-scope entrypoint reaches exits 0; a diff a fully-qualified import reaches exits
    1 (control)."""
    clean = make_repo()
    clean.config(code_roots=["app"], entrypoint_stems=("run",))
    clean.write("app/run.py", "import app.pkg.reached\nif __name__ == '__main__':\n    pass\n")
    clean.write("app/pkg/reached.py", "X = 1\n")
    clean.write("app/pkg/orphan.py", "O = 1\n")
    clean.graph(UNMODELLED_GRAPH)
    cbase = clean.commit("base")
    clean.write("app/pkg/orphan.py", "O = 2\n")  # nobody imports orphan
    clean.commit("change")
    rc = clean.run("spec_graph_x.yaml", cbase)
    assert rc.returncode == 0

    fire = make_repo()
    fire.config(code_roots=["app"], entrypoint_stems=("run",))
    fire.write("app/run.py", "import app.pkg.reached\nif __name__ == '__main__':\n    pass\n")
    fire.write("app/pkg/reached.py", "X = 1\n")
    fire.graph(UNMODELLED_GRAPH)
    fbase = fire.commit("base")
    fire.write("app/pkg/reached.py", "X = 2\n")
    fire.commit("change")
    rf = fire.run("spec_graph_x.yaml", fbase)
    assert rf.returncode == 1
    assert "reached" in rf.stdout


def test_changed_module_under_tests_path_is_excluded(make_repo):
    """A changed module whose path contains /tests/ is excluded from the changed set (no finding);
    the same change outside /tests/ fires (control)."""
    excluded = make_repo()
    excluded.config(code_roots=["app"], entrypoint_stems=("run",))
    excluded.write(
        "app/run.py", "import app.tests.fixturemod\nif __name__ == '__main__':\n    pass\n"
    )
    excluded.write("app/tests/fixturemod.py", "X = 1\n")
    excluded.graph(UNMODELLED_GRAPH)
    ebase = excluded.commit("base")
    excluded.write("app/tests/fixturemod.py", "X = 2\n")  # under /tests/ → excluded from `changed`
    excluded.commit("change")
    re_ = excluded.run("spec_graph_x.yaml", ebase)
    assert re_.returncode == 0

    ctl = make_repo()
    ctl.config(code_roots=["app"], entrypoint_stems=("run",))
    ctl.write("app/run.py", "import app.pkg.includedmod\nif __name__ == '__main__':\n    pass\n")
    ctl.write("app/pkg/includedmod.py", "X = 1\n")
    ctl.graph(UNMODELLED_GRAPH)
    cbase = ctl.commit("base")
    ctl.write("app/pkg/includedmod.py", "X = 2\n")
    ctl.commit("change")
    rc = ctl.run("spec_graph_x.yaml", cbase)
    assert rc.returncode == 1
    assert "includedmod" in rc.stdout


# ── step-7 resolved demands ──────────────────────────────────────────────────
def test_cross_package_same_stem_no_false_reach(make_repo):
    """A same-stem module changed in a different package than the one imported yields no false
    reach (PATH-granular); the imported package's module changed does fire (control)."""
    # Negative: entrypoint imports pkg_b.driver; pkg_a/driver.py (a different package, same stem)
    # changes while pkg_b/driver.py does not. Stem-granular HEAD false-fires; path-granular → silent.
    neg = make_repo()
    neg.config(code_roots=["app"], entrypoint_stems=("run",))
    neg.write("app/run.py", "import app.pkg_b.driver\nif __name__ == '__main__':\n    pass\n")
    neg.write("app/pkg_a/driver.py", "A = 1\n")
    neg.write("app/pkg_b/driver.py", "B = 1\n")
    neg.graph(UNMODELLED_GRAPH)
    nbase = neg.commit("base")
    neg.write("app/pkg_a/driver.py", "A = 2\n")  # the NOT-imported package's driver changes
    neg.commit("change")
    rn = neg.run("spec_graph_x.yaml", nbase)
    assert rn.returncode == 0  # the imported pkg_b/driver.py did not change → no reach

    # Control: the imported package's driver changes → fires.
    ctl = make_repo()
    ctl.config(code_roots=["app"], entrypoint_stems=("run",))
    ctl.write("app/run.py", "import app.pkg_b.driver\nif __name__ == '__main__':\n    pass\n")
    ctl.write("app/pkg_a/driver.py", "A = 1\n")
    ctl.write("app/pkg_b/driver.py", "B = 1\n")
    ctl.graph(UNMODELLED_GRAPH)
    cbase = ctl.commit("base")
    ctl.write("app/pkg_b/driver.py", "B = 2\n")
    ctl.commit("change")
    rc = ctl.run("spec_graph_x.yaml", cbase)
    assert rc.returncode == 1
    assert "app/run.py" in rc.stdout
    assert "driver" in rc.stdout


def test_symbol_import_with_unrelated_same_stem_change_no_reach(make_repo):
    """`from pkg import summarize` (a function, no pkg/summarize.py) with an unrelated same-stem
    module changed elsewhere yields no reach; a real changed submodule does fire (control)."""
    neg = make_repo()
    neg.config(code_roots=["app"], entrypoint_stems=("run",))
    neg.write("app/run.py", "from app.pkg import summarize\nif __name__ == '__main__':\n    pass\n")
    neg.write("app/pkg/text.py", "def summarize():\n    return 1\n")  # summarize is a symbol here
    neg.write("app/other/summarize.py", "S = 1\n")  # unrelated module that happens to share the stem
    neg.graph(UNMODELLED_GRAPH)
    nbase = neg.commit("base")
    neg.write("app/other/summarize.py", "S = 2\n")
    neg.commit("change")
    rn = neg.run("spec_graph_x.yaml", nbase)
    assert rn.returncode == 0  # no pkg/summarize.py to resolve to; other/summarize.py not imported

    ctl = make_repo()
    ctl.config(code_roots=["app"], entrypoint_stems=("run",))
    ctl.write("app/run.py", "from app.pkg import realmod\nif __name__ == '__main__':\n    pass\n")
    ctl.write("app/pkg/realmod.py", "X = 1\n")
    ctl.graph(UNMODELLED_GRAPH)
    cbase = ctl.commit("base")
    ctl.write("app/pkg/realmod.py", "X = 2\n")
    ctl.commit("change")
    rc = ctl.run("spec_graph_x.yaml", cbase)
    assert rc.returncode == 1
    assert "realmod" in rc.stdout


def test_reach_only_through_outside_coderoots_is_accepted_gap(make_repo):
    """Reach that passes only through a module OUTSIDE codeRoots is an accepted gap (silent); a
    direct in-roots reach fires (control)."""
    repo = make_repo()
    # codeRoots is only app/ ; the `outside/` tree is not a code root.
    repo.config(code_roots=["app"], entrypoint_stems=("run", "loop"))
    # gap: loop → outside.mid (outside codeRoots) → app.pkg.gapleaf. Reachable only transitively
    # through an outside-codeRoots module → 1-hop HEAD misses it, and the bounded fix must too.
    repo.write("app/loop.py", "import outside.mid\nif __name__ == '__main__':\n    pass\n")
    repo.write("outside/mid.py", "import app.pkg.gapleaf\n")
    repo.write("app/pkg/gapleaf.py", "X = 1\n")
    # control: run → app.pkg.ctrlleaf directly, in-roots → fires today.
    repo.write("app/run.py", "import app.pkg.ctrlleaf\nif __name__ == '__main__':\n    pass\n")
    repo.write("app/pkg/ctrlleaf.py", "X = 1\n")
    repo.graph(UNMODELLED_GRAPH)
    base = repo.commit("base")
    repo.write("app/pkg/gapleaf.py", "X = 2\n")
    repo.write("app/pkg/ctrlleaf.py", "X = 2\n")
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert "app/run.py" in r.stdout and "ctrlleaf" in r.stdout  # in-roots control fires
    assert "app/loop.py" not in r.stdout  # outside-codeRoots-only reach stays silent
    assert "gapleaf" not in r.stdout


def test_co_firing_finding_reports_both_import_and_subprocess(make_repo):
    """A finding for an entrypoint that trips BOTH arms reports both the import reach and the
    subprocess re-exec hazard (neither masks the other)."""
    repo = make_repo()
    repo.config(code_roots=["app"], entrypoint_stems=("run",))
    repo.write(
        "app/run.py",
        "import subprocess, sys\n"
        "import app.pkg.impmod\n"
        "subprocess.run([sys.executable, 'app/pkg/subtarget.py'])\n"
        "if __name__ == '__main__':\n    pass\n",
    )
    repo.write("app/pkg/impmod.py", "X = 1\n")
    repo.write("app/pkg/subtarget.py", "Y = 1\n")
    repo.graph(UNMODELLED_GRAPH)
    base = repo.commit("base")
    repo.write("app/pkg/impmod.py", "X = 2\n")  # import arm fires (fully-qualified, works today)
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert "app/run.py" in r.stdout
    assert "impmod" in r.stdout  # the import reach
    assert "subtarget" in r.stdout  # the subprocess re-exec hazard — must co-appear, not be masked


# ── cold-reconciler composition holes ────────────────────────────────────────
def test_cross_package_same_stem_no_false_reach_transitive(make_repo):
    """PATH-granular ∧ transitive (F1): a same-stem module changed in a package the entrypoint only
    reaches through a DIFFERENT package's transitive closure yields no false reach; the actually
    reached same-stem module changed does fire (control). Forces path-granular comparison THROUGH
    the closure, not just the first hop."""
    # Negative: run → pkg_b.entry → pkg_b.driver. pkg_a/driver.py (a different package, same stem)
    # changes while the reached pkg_b/driver.py does not → no reach.
    neg = make_repo()
    neg.config(code_roots=["app"], entrypoint_stems=("run",))
    neg.write("app/run.py", "import app.pkg_b.entry\nif __name__ == '__main__':\n    pass\n")
    neg.write("app/pkg_b/entry.py", "from . import driver\n")  # → app/pkg_b/driver.py
    neg.write("app/pkg_b/driver.py", "B = 1\n")
    neg.write("app/pkg_a/driver.py", "A = 1\n")  # unrelated, SAME STEM, never imported
    neg.graph(UNMODELLED_GRAPH)
    nbase = neg.commit("base")
    neg.write("app/pkg_a/driver.py", "A = 2\n")  # the NOT-imported same-stem module changes
    neg.commit("change")
    rn = neg.run("spec_graph_x.yaml", nbase)
    assert rn.returncode == 0  # only pkg_a/driver.py changed, not the reached pkg_b/driver.py
    assert "app/run.py" not in rn.stdout  # run.py is not credited for a pkg_a reach

    # Control (same shape): the transitively-reached pkg_b/driver.py changes → run.py fires.
    ctl = make_repo()
    ctl.config(code_roots=["app"], entrypoint_stems=("run",))
    ctl.write("app/run.py", "import app.pkg_b.entry\nif __name__ == '__main__':\n    pass\n")
    ctl.write("app/pkg_b/entry.py", "from . import driver\n")  # → app/pkg_b/driver.py
    ctl.write("app/pkg_b/driver.py", "B = 1\n")
    ctl.write("app/pkg_a/driver.py", "A = 1\n")
    ctl.graph(UNMODELLED_GRAPH)
    cbase = ctl.commit("base")
    ctl.write("app/pkg_b/driver.py", "B = 2\n")  # the transitively-imported one changes
    ctl.commit("change")
    rc = ctl.run("spec_graph_x.yaml", cbase)
    assert rc.returncode == 1
    assert "app/run.py" in rc.stdout
    assert "driver" in rc.stdout


def test_co_firing_finding_with_transitive_import_and_subprocess(make_repo):
    """Both arms fire, and the import reach is TRANSITIVE (F2): the finding for an entrypoint that
    transitively imports a changed leaf AND subprocesses a project module carries BOTH the leaf
    (transitive import reach) and the subtarget (subprocess hazard) — neither masks the other."""
    repo = make_repo()
    repo.config(code_roots=["app"], entrypoint_stems=("run",))
    repo.write(
        "app/run.py",
        "import subprocess, sys\n"
        "import app.pkg.mid\n"
        "subprocess.run([sys.executable, 'app/pkg/subtarget.py'])\n"
        "if __name__ == '__main__':\n    pass\n",
    )
    repo.write("app/pkg/mid.py", "from . import leaf\n")  # → app/pkg/leaf.py
    repo.write("app/pkg/leaf.py", "X = 1\n")  # the transitively-reached import target
    repo.write("app/pkg/subtarget.py", "Y = 1\n")  # the subprocess target (project module)
    repo.graph(UNMODELLED_GRAPH)
    base = repo.commit("base")
    repo.write("app/pkg/leaf.py", "X = 2\n")  # transitively-reached leaf changes
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert "app/run.py" in r.stdout
    assert "leaf" in r.stdout  # transitive import reach (RED at HEAD: 1-hop misses leaf)
    assert "subtarget" in r.stdout  # subprocess hazard — co-appears with the transitive reach


def test_modelled_intermediate_does_not_suppress_unmodelled_entrypoint(make_repo):
    """Suppression is keyed on the ENTRYPOINT, not a modelled module on the reach path (F3): an
    unmodelled entrypoint that reaches a changed leaf through a MODELLED intermediate still fires —
    the intermediate's presence in the graph does not suppress the entrypoint."""
    repo = make_repo()
    repo.config(code_roots=["app"], entrypoint_stems=("loop",))
    repo.write("app/loop.py", "from app.pkg import mid\nif __name__ == '__main__':\n    pass\n")
    repo.write("app/pkg/mid.py", "from . import leaf\n")  # → app/pkg/leaf.py
    repo.write("app/pkg/leaf.py", "X = 1\n")
    repo.graph(_graph_modelling("mid"))  # models the INTERMEDIATE `mid`, NOT the entrypoint `loop`
    base = repo.commit("base")
    repo.write("app/pkg/leaf.py", "X = 2\n")
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base)
    assert r.returncode == 1
    assert "app/loop.py" in r.stdout  # loop fires despite `mid` being modelled on its reach path
    assert "leaf" in r.stdout


def test_whole_repo_diff_anchoring_survives_subdir_cwd(make_repo):
    """The changed-set git diff is anchored at the repo root, not the process CWD (F4): running the
    tool from a SUBDIRECTORY of the fixture still surfaces a change under a sibling subtree — the
    whole-repo diff must not silently scope to the subdir and come back empty. GREEN at HEAD (the
    code anchors git at repo_root today) — a regression guard for the Q2 `_changed_stems` rewrite."""
    repo = make_repo()
    repo.config(code_roots=["app"], entrypoint_stems=("run",))
    repo.write("app/run.py", "import app.pkg.mod\nif __name__ == '__main__':\n    pass\n")
    repo.write("app/pkg/mod.py", "X = 1\n")
    repo.graph(UNMODELLED_GRAPH)
    base = repo.commit("base")
    repo.write("app/pkg/mod.py", "X = 2\n")
    repo.commit("change")
    r = repo.run("spec_graph_x.yaml", base, subdir="app")  # run from a subdirectory, not the root
    assert r.returncode == 1
    assert "app/run.py" in r.stdout  # the finding still appears — diff anchored at the repo root
    assert "mod" in r.stdout
