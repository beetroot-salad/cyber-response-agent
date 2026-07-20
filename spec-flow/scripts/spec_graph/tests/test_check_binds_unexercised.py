"""Binding suite for check_binds' unexercised-seam check.

Every test drives the REAL `check_binds.py` via subprocess against a throwaway suite dir (a
graph plus the `*.py` beside it — the artifact rule's layout), and asserts on the observable
payload: the exit code and the demand id named in the finding, never exact wording.

The defect this check exists to catch, from #540's own graph. `d_every_bash_enabled_role_has_a_box`
bound `drives(_tool_bash->BoxExecutor)` and discharged it with:

    deps = bind(defn, run_dir, ...)                 # no box= threaded
    assert isinstance(deps.box, box.BoxExecutor)

`AgentDeps.box` defaults to `field(default_factory=BoxExecutor)`, so the inert default and a
live attached container are the SAME TYPE: the assertion holds no matter what, and it stayed
green through a change that left two bash-enabled roles with no box. The demand's content is
ATTACHMENT; the test asserts the field's TYPE.

The rule is deliberately narrow, and the negative cases below are the reason. `B` absent from
the test entirely is NOT a finding — a test driving the real loop reaches `B` through production
wiring and never names it. Only "named, but exclusively inside an `assert`" is flagged: the test
knows the seam well enough to name it and never once puts it to work.
"""
from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

import pytest

from conftest import SPEC_GRAPH_DIR, run_script

DEFAULT_CHECK_BINDS = SPEC_GRAPH_DIR / "check_binds.py"

GRAPH = """\
schema_version: 1
demands:
  - id: d_seam
    kind: parity
    form: test
    discharged_by: test_seam
    binds: ["drives(_tool_bash->BoxExecutor)"]
"""


def _suite(tmp_path: Path, body: str, graph: str = GRAPH) -> Path:
    """A suite dir: one graph plus the test file beside it, as the artifact rule commits them."""
    d = tmp_path / "suite"
    d.mkdir(exist_ok=True)
    (d / "spec_graph_x.yaml").write_text(graph, encoding="utf-8")
    (d / "test_x.py").write_text(textwrap.dedent(body).lstrip("\n"), encoding="utf-8")
    return d


def _run(suite: Path) -> subprocess.CompletedProcess[str]:
    # `$CHECK_BINDS_PATH` is the null-stub discrimination seam, mirroring conftest's
    # `$CHECK_ACTORS_PATH`: pointed at a no-op stub, every positive test below must go red.
    check = os.environ.get("CHECK_BINDS_PATH", str(DEFAULT_CHECK_BINDS))
    return run_script(check, "spec_graph_x.yaml", cwd=suite, timeout=60)


def test_a_seam_named_only_in_an_assertion_is_flagged(tmp_path):
    """The defect shape: the test constructs its subject and asserts the seam's TYPE, never
    driving it. `BoxExecutor` appears exactly once, inside the assert."""
    suite = _suite(tmp_path, '''
        def test_seam(tmp_path):
            """Every bash-enabled role is bound with a box."""
            deps = bind(MAIN_DEF, tmp_path)
            assert isinstance(deps.box, BoxExecutor)
    ''')
    p = _run(suite)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "d_seam" in p.stdout
    assert "UNEXERCISED" in p.stdout


def test_a_seam_constructed_and_threaded_is_not_flagged(tmp_path):
    """POSITIVE CONTROL. The same demand, discharged by a test that builds the seam and hands
    it in — `BoxExecutor` lives outside the assert. Without this the rule could flag every
    `drives` demand and still pass the test above."""
    suite = _suite(tmp_path, '''
        def test_seam(tmp_path):
            """The tool executes through the injected box."""
            t = RecordingTransport(framed(0, b"out", b""))
            deps = bind(MAIN_DEF, tmp_path, box=BoxExecutor(transport=t))
            shown = _bash(deps, "cat x")
            assert t.calls, "the bash tool did not reach the box"
            assert "out" in shown
    ''')
    p = _run(suite)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "UNEXERCISED" not in p.stdout


def test_a_seam_never_named_is_not_flagged(tmp_path):
    """The false-positive the narrowness buys. A test that drives the real loop reaches the
    seam through production wiring and never names it — `test_the_existing_e2e_bash_corpus_...`
    reaches `_tool_bash` only via the driver's tool registration. Absence is not inspection."""
    suite = _suite(tmp_path, '''
        def test_seam(tmp_path):
            """The existing corpus still completes through the real loop."""
            main = ReplayFn([Turn(text="done")])
            drive(tmp_path, main=main)
            assert main.calls == 1
    ''')
    p = _run(suite)
    assert p.returncode == 0, p.stdout + p.stderr


def test_a_seam_used_outside_and_inside_an_assertion_is_not_flagged(tmp_path):
    """Naming the seam in an assertion is fine — it is naming it ONLY there that is the defect.
    A test may legitimately both exercise and assert on the same symbol."""
    suite = _suite(tmp_path, '''
        def test_seam(tmp_path):
            """The box is built and its identity is asserted."""
            b = BoxExecutor(transport=t)
            out = _bash(bind(MAIN_DEF, tmp_path, box=b), "cat x")
            assert isinstance(b, BoxExecutor) and out
    ''')
    p = _run(suite)
    assert p.returncode == 0, p.stdout + p.stderr


def test_an_exercise_waiver_silences_a_named_demand(tmp_path):
    """A deliberate structural demand records itself rather than going quiet: the waiver is
    keyed by demand id AND seam name, so waiving one demand cannot silence another."""
    graph = GRAPH + 'exercise_waivers:\n  d_seam: ["BoxExecutor"]\n'
    suite = _suite(tmp_path, '''
        def test_seam(tmp_path):
            """Every bash-enabled role is bound with a box."""
            deps = bind(MAIN_DEF, tmp_path)
            assert isinstance(deps.box, BoxExecutor)
    ''', graph=graph)
    p = _run(suite)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "UNEXERCISED" not in p.stdout


def test_a_waiver_for_a_different_demand_does_not_silence_this_one(tmp_path):
    """NEGATIVE CONTROL for the waiver: keyed lookup, not a global mute."""
    graph = GRAPH + 'exercise_waivers:\n  d_other: ["BoxExecutor"]\n'
    suite = _suite(tmp_path, '''
        def test_seam(tmp_path):
            """Every bash-enabled role is bound with a box."""
            deps = bind(MAIN_DEF, tmp_path)
            assert isinstance(deps.box, BoxExecutor)
    ''', graph=graph)
    p = _run(suite)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "d_seam" in p.stdout


def test_the_prose_orphan_check_still_reports_and_counts_separately(tmp_path):
    """SURVIVAL. The pre-existing prose⊄binds check keeps working alongside the new one, and
    the summary counts the two kinds apart — collapsing them would hide which discipline
    slipped. Here the docstring threads `salt=deps.salt`, a concept another demand binds."""
    graph = """\
schema_version: 1
demands:
  - id: d_seam
    kind: parity
    form: test
    discharged_by: test_seam
    binds: ["drives(_tool_bash->BoxExecutor)"]
  - id: d_salt
    kind: behavior
    form: test
    discharged_by: test_salt
    binds: [salt]
"""
    suite = _suite(tmp_path, '''
        def test_seam(tmp_path):
            """The prompt threads salt=deps.salt into the run."""
            b = BoxExecutor(transport=t)
            assert _bash(bind(MAIN_DEF, tmp_path, box=b), "cat x")

        def test_salt(tmp_path):
            """The salt is carried."""
            assert True
    ''', graph=graph)
    p = _run(suite)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "ORPHAN" in p.stdout
    assert "UNEXERCISED" not in p.stdout
    assert "1 prose-orphan(s), 0 unexercised seam(s)" in p.stdout


@pytest.mark.parametrize("missing", ["dangling", "no_docstring"])
def test_a_body_is_still_checked_when_the_prose_is_absent(tmp_path, missing):
    """A test with no docstring still has a BODY, so the exercise check must run on it — the
    docstring gate returns early for the prose scan and must not take this check with it. The
    dangling case has no body at all and correctly reports only the dangling pointer."""
    body = '''
        def test_seam(tmp_path):
            deps = bind(MAIN_DEF, tmp_path)
            assert isinstance(deps.box, BoxExecutor)
    ''' if missing == "no_docstring" else '''
        def test_unrelated(tmp_path):
            """Nothing to do with the demand."""
            assert True
    '''
    p = _run(_suite(tmp_path, body))
    assert p.returncode == 1, p.stdout + p.stderr
    if missing == "no_docstring":
        assert "UNEXERCISED" in p.stdout
    else:
        assert "dangles" in p.stdout
