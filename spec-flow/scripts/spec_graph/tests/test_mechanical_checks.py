"""Binding suite for the mechanized write-tests gate: check_gate, check_frontiers,
check_lint, check_claims' spend-point pass, check_calls, check_stub, and trace.

Every test drives the real script via subprocess (the house style — no injection seam
exists in the scripts) and asserts on the observable payload: the exit code and the
identity of the element named in the finding, never exact wording. The exit-code
contract is shared across the family: 0 clean, 1 the check looked and found something,
2 it could not look (never a silent pass).
"""
from __future__ import annotations

import sys
import textwrap
from pathlib import Path

from conftest import SPEC_GRAPH_DIR, run_script  # run_script re-exported for the fixes suites

# The rule roster and version set are READ from the schema, never restated: a fixture that
# restates them goes stale the moment one grows, and then silently exercises the
# missing-entry arm instead of the mechanics it names (#883).
sys.path.insert(0, str(SPEC_GRAPH_DIR))
import _schema  # noqa: E402 — resolvable only after the sys.path line above


# ---------------------------------------------------------------------------
# check_gate
# ---------------------------------------------------------------------------

def _evaluated(version: int = 1, **fired: bool) -> str:
    """A `gate.evaluated` block recording every rule a graph at `version` OWES an entry for
    (`_schema.SINCE`), `fired: true` unless named otherwise.

    Derived rather than written out: a restated roster goes stale the moment a rule is
    added, and a stale one does not fail loudly — it makes every test using it exercise the
    missing-entry arm instead of the mechanics it names."""
    rules = [r for r in _schema.RULES if _schema.SINCE.get(r, 1) <= version]
    return "gate:\n  evaluated:\n" + "".join(
        f"    - {{rule: {r}, fired: {str(fired.get(r, True)).lower()}}}\n" for r in rules
    )


# Every rule this graph owes, `fired: true` — the common case.
_EVALUATED_ALL = _evaluated()

# Same, but R4 recorded `fired: false` — the slot-vs-evaluated conflict case.
_EVALUATED_R4_FALSE = _evaluated(R4=False)

# One R4 trigger: a design-provenance domain boundary with a read edge and one
# distinguished member. `demands:` decides whether the trigger is answered.
_R4_GRAPH = """\
schema_version: 1
design: "#t"
base: abc
demands:
{demands}
structure:
  axes: []
  actors:
    - {{id: reader, frame: leg, provenance: design}}
  boundaries:
    - id: knob
      provenance: design
      facets:
        domain: {{type: int, default: 30, distinguished: [0], falsy_valid: true}}
  interacts:
    - {{from: reader, to: knob, mode: read, via: env, provenance: design}}
{gate}
"""

_D_CELL = ('  - {id: d_cell, kind: domain-outcome, form: test, discharged_by: test_zero,\n'
           '     binds: ["knob.domain.distinguished[0]"]}\n')


def test_gate_unanswered_trigger_exits_1_and_names_the_cell(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _R4_GRAPH.format(demands="  []", gate=_EVALUATED_ALL))
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    assert "knob.domain.distinguished[0]" in p.stdout and "UNANSWERED" in p.stdout


def test_gate_bound_cell_is_answered_and_exits_0(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _R4_GRAPH.format(demands=_D_CELL, gate=_EVALUATED_ALL))
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 0, p.stdout + p.stderr


def test_gate_fired_false_conflicting_with_computed_trigger_is_flagged(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _R4_GRAPH.format(demands="  []", gate=_EVALUATED_R4_FALSE))
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    assert "FIRED-FALSE" in p.stdout and "R4" in p.stdout


def test_gate_missing_evaluated_entry_reads_as_skipped(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _R4_GRAPH.format(demands=_D_CELL, gate="gate: {evaluated: []}"))
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    assert "EVALUATED" in p.stdout and "R6" in p.stdout


# The `_schema.SINCE` gating: a rule is owed a `gate.evaluated` entry only from the artifact
# version it was introduced at. Without this, adding a rule makes every graph in the corpus
# dirty at once, and the only ways out are re-baselining unrelated history (masking a first
# real finding in every graph that was clean) or leaving the corpus red (#883).

#: Exactly what a version-1 run could record. Applied to a version-2 graph below, it is the
#: omission the gating must still catch.
_EVALUATED_V1 = _evaluated(1)


def test_a_rule_newer_than_the_graphs_schema_version_is_not_owed_an_entry(make_repo):
    """R8 arrived at schema_version 2. A version-1 graph recording R0–R7 is COMPLETE: the
    run that would have evaluated R8 predates the rule, so demanding the entry would be
    demanding a record of something that could not have happened."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _R4_GRAPH.format(demands=_D_CELL, gate=_EVALUATED_V1))
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "R8" not in p.stdout


def test_a_rule_at_or_below_the_graphs_schema_version_is_owed_its_entry(make_repo):
    """The other direction, and the half that makes the gating worth having: at the version
    the rule was introduced, the same omission is a finding. A version gate that only ever
    excused things would be indistinguishable from deleting the check."""
    r = make_repo()
    r.config(code_roots=[])
    v2 = _R4_GRAPH.replace("schema_version: 1", "schema_version: 2")
    r.write("g.yaml", v2.format(demands=_D_CELL, gate=_EVALUATED_V1))
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    assert "EVALUATED" in p.stdout and "R8" in p.stdout


def test_a_graph_declaring_no_schema_version_owes_only_the_oldest_contract(make_repo):
    """An absent declaration reads as version 1 — the contract owing the fewest entries.
    Naming the omission is check_lint's job (it validates the closed version set); check_gate
    piling a second finding on top would report one defect as two."""
    r = make_repo()
    r.config(code_roots=[])
    unversioned = _R4_GRAPH.replace("schema_version: 1\n", "")
    r.write("g.yaml", unversioned.format(demands=_D_CELL, gate=_EVALUATED_V1))
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 0, p.stdout + p.stderr


def test_gate_dangling_binds_address_is_an_r0_finding(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    dangling = ('  - {id: d_ghost, kind: behavior, form: test, discharged_by: test_g,\n'
                '     binds: ["no_such_element"]}\n')
    r.write("g.yaml", _R4_GRAPH.format(demands=_D_CELL + dangling, gate=_EVALUATED_ALL))
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    assert "no_such_element" in p.stdout and "R0" in p.stdout


def test_gate_residue_prints_the_skeleton_and_exits_0(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _R4_GRAPH.format(demands="  []", gate="gate: {evaluated: []}"))
    p = run_script("check_gate.py", "g.yaml", "--residue", cwd=r.root)
    assert p.returncode == 0
    assert "R4" in p.stdout and "knob.domain.distinguished[0]" in p.stdout


def test_gate_r2_uncovered_key_axis_fires_and_a_recorded_answer_silences(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    graph = """\
schema_version: 1
design: "#t"
base: abc
demands: []
structure:
  axes: [stem]
  actors:
    - {id: w1, frame: leg, provenance: design}
    - {id: w2, frame: leg, provenance: design}
  boundaries:
    - id: sink
      provenance: design
      facets:
        identity: {key_axes: [stem], evidence: {nl: "read off the path template"},
                   sharing: unique-key}
  interacts:
    - {from: w1, to: sink, mode: write, via: fs, provenance: design, interpolates: [stem]}
    - {from: w2, to: sink, mode: write, via: fs, provenance: design, interpolates: []}
""" + _EVALUATED_ALL
    r.write("g.yaml", graph)
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    assert "does not cover key axis `stem`" in p.stdout
    # The same graph with the R2 question recorded as an obligation: coverage is heard.
    r.write("g2.yaml", graph + (
        "  obligations:\n"
        "    - {rule: R2, element: sink.identity, witness: w, discharged_by: d_u}\n"
    ))
    p2 = run_script("check_gate.py", "g2.yaml", cwd=r.root)
    # 0, not just substring-absence: without the returncode pin this arm stayed green
    # when check_gate crashed (exit 2) or found something unrelated (exit 1).
    assert p2.returncode == 0, p2.stdout + p2.stderr
    assert "does not cover key axis" not in p2.stdout


# ---------------------------------------------------------------------------
# check_frontiers
# ---------------------------------------------------------------------------

def _frontier(path: Path, name: str, meta: str, digest: str = "ok") -> None:
    (path / name).write_text(f"---\n{meta}---\n\n## Digest\n\n{digest}\n", encoding="utf-8")


def test_frontiers_echo_mismatch_is_a_conservation_finding(tmp_path):
    d = tmp_path / "frontiers"
    d.mkdir()
    _frontier(d, "10-brief.md", "phase: A\nstatus: complete\ninventory: {claims: 3}\n")
    _frontier(d, "20-demands.md",
              "phase: A\nstatus: complete\ninventory: {demands: 2}\n"
              "inputs: [{path: 10-brief.md, inventory_echo: {claims: 4}}]\n")
    p = run_script("check_frontiers.py", str(d), cwd=tmp_path)
    assert p.returncode == 1
    assert "inventory_echo" in p.stdout and "10-brief.md" in p.stdout


def test_frontiers_clean_chain_exits_0_and_external_inputs_are_tolerated(tmp_path):
    d = tmp_path / "frontiers"
    d.mkdir()
    _frontier(d, "10-brief.md",
              "phase: A\nstatus: complete\ninventory: {claims: 3}\n"
              'inputs: [{path: "gh-issue-1 thread", inventory_echo: {claims: 1}}]\n')
    _frontier(d, "20-demands.md",
              "phase: A\nstatus: complete\ninventory: {demands: 2}\n"
              "inputs: [{path: 10-brief.md, inventory_echo: {claims: 3}}]\n")
    p = run_script("check_frontiers.py", str(d), cwd=tmp_path)
    assert p.returncode == 0, p.stdout


def test_frontiers_digest_over_cap_and_missing_input_flag(tmp_path):
    d = tmp_path / "frontiers"
    d.mkdir()
    _frontier(d, "30-premises-author.md",
              "phase: B\nstatus: complete\ninventory: {premises: 1}\n"
              "inputs: [{path: 10-brief.md, inventory_echo: {claims: 1}}]\n",
              digest="\n".join(f"line {i}" for i in range(20)))
    p = run_script("check_frontiers.py", str(d), cwd=tmp_path)
    assert p.returncode == 1
    assert "digest" in p.stdout.lower() and "10-brief.md" in p.stdout


def test_frontiers_dispositions_sum_rule(tmp_path):
    d = tmp_path / "frontiers"
    d.mkdir()
    _frontier(d, "40-premises.md", "phase: C\nstatus: complete\ninventory: {premises: 10}\n")
    _frontier(d, "45-dispositions.md",
              "phase: C\nstatus: complete\n"
              "inventory: {consensus: 5, forks: 2, silent_branches: 1, drops: 1}\n"
              "inputs: [{path: 40-premises.md, inventory_echo: {premises: 10}}]\n")
    p = run_script("check_frontiers.py", str(d), cwd=tmp_path)
    assert p.returncode == 1
    assert "9" in p.stdout and "10" in p.stdout  # 5+2+1+1 = 9 ≠ 10 premises consumed


def test_frontiers_resume_reports_design_refuted_as_a_halt(tmp_path):
    d = tmp_path / "frontiers"
    d.mkdir()
    _frontier(d, "10-brief.md", "phase: A\nstatus: design-refuted\ninventory: {claims: 1}\n")
    p = run_script("check_frontiers.py", str(d), "--resume", cwd=tmp_path)
    assert p.returncode == 0
    assert "design-refuted" in p.stdout and "halted" in p.stdout


# ---------------------------------------------------------------------------
# check_lint
# ---------------------------------------------------------------------------

_MINIMAL = """\
schema_version: {v}
design: "#t"
base: abc
demands: []
structure:
  boundaries: []
"""


def test_lint_accepts_every_declared_schema_version_and_no_others(make_repo):
    """`schema_version` is a closed SET, not a pin. It has to admit every contract the
    corpus actually holds — `_schema.SINCE` reads the declaration to decide which rules a
    graph owes an entry for, so a pin would force each new rule to be paid for by
    re-baselining history — and it has to keep refusing values outside the set, or the
    field stops being a contract at all."""
    for version in _schema.SCHEMA_VERSIONS:
        r = make_repo()
        r.config(code_roots=[])
        r.write("g.yaml", _MINIMAL.format(v=version))
        p = run_script("check_lint.py", "g.yaml", cwd=r.root)
        assert "schema_version" not in p.stdout, f"v{version} rejected: {p.stdout}"

    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _MINIMAL.format(v=max(_schema.SCHEMA_VERSIONS) + 1))
    p = run_script("check_lint.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    assert "schema_version" in p.stdout


def test_lint_flags_vocabulary_and_form_conditional_defects(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", """\
schema_version: 1
design: "#t"
base: abc
demands:
  - {id: d1, kind: not-a-kind, form: test, binds: [x],
     outcome: {nl: "prose on a pointer"}}
  - {id: d2, kind: behavior, form: waiver, binds: [x]}
structure:
  boundaries:
    - {id: x, provenance: code, facets: {content: {}}}
""")
    p = run_script("check_lint.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    out = p.stdout
    assert "not-a-kind" in out                   # closed kind vocabulary
    assert "discharged_by" in out                # form:test with no pointer
    assert "inlines an `outcome`" in out         # pointer carrying prose
    assert "outcome" in out and "d2" in out      # waiver with no outcome sentence
    assert "unknown facet `content`" in out


def test_lint_clean_minimal_graph_exits_0(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", """\
schema_version: 1
design: "#t"
base: abc
demands:
  - {id: d1, kind: behavior, form: test, discharged_by: test_a, binds: [x]}
structure:
  boundaries:
    - {id: x, provenance: code, facets: {}}
""")
    p = run_script("check_lint.py", "g.yaml", cwd=r.root)
    assert p.returncode == 0, p.stdout


# ---------------------------------------------------------------------------
# check_claims — the spend-point pass
# ---------------------------------------------------------------------------

_CLAIMS_GRAPH = """\
schema_version: 1
demands:
  - {{id: w1, kind: behavior, form: waiver, binds: [x],
     outcome: {{nl: "declined — out of scope"}}{cites}}}
claims:
  - {{id: c_ok, kind: behavior, claim: "x", probe: "ran it", probe_kind: executed,
     observed: "y", verdict: holds}}
  - {{id: c_unprobed, kind: behavior, claim: "x", probe: "", observed: "", verdict: unprobed}}
"""


def test_claims_waiver_without_cites_is_a_citation_finding(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _CLAIMS_GRAPH.format(cites=""))
    p = run_script("check_claims.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    assert "CITATION" in p.stdout and "w1" in p.stdout


def test_claims_cited_probed_claim_passes_and_unprobed_or_dangling_fail(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("ok.yaml", _CLAIMS_GRAPH.format(cites=", cites: [c_ok]"))
    assert run_script("check_claims.py", "ok.yaml", cwd=r.root).returncode == 0
    r.write("unprobed.yaml", _CLAIMS_GRAPH.format(cites=", cites: [c_unprobed]"))
    p = run_script("check_claims.py", "unprobed.yaml", cwd=r.root)
    assert p.returncode == 1 and "c_unprobed" in p.stdout
    r.write("dangling.yaml", _CLAIMS_GRAPH.format(cites=", cites: [c_ghost]"))
    p = run_script("check_claims.py", "dangling.yaml", cwd=r.root)
    assert p.returncode == 1 and "c_ghost" in p.stdout


def test_claims_judgment_rule_fired_false_requires_cites(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", """\
schema_version: 1
claims:
  - {id: c_ok, kind: reachability, claim: "x", probe: "break-attempt", probe_kind: executed,
     observed: "survived", verdict: unrefuted}
gate:
  evaluated:
    - {rule: R6, fired: false}
    - {rule: R1, fired: false}
""")
    p = run_script("check_claims.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    assert "R6" in p.stdout
    assert "R1" not in p.stdout  # computed rule — check_gate verifies it, not a citation


# ---------------------------------------------------------------------------
# check_calls + check_stub (shared target identification)
# ---------------------------------------------------------------------------

def _suite_repo(make_repo):
    """A fixture repo whose suite imports `appx.summarize` — a project-rooted module
    that does not exist: the not-yet-written target."""
    r = make_repo()
    r.config(code_roots=["appx"])
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
    r.config(code_roots=["appx"])
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


def test_nullstub_recorded_pass_in_the_graph_is_accepted(make_repo):
    r = _suite_repo(make_repo)
    r.write("tests/spec/spec_graph_t.yaml", textwrap.dedent("""\
        schema_version: 1
        handoff:
          nullstub_passes: ["test_nothing_about_the_target — structure"]
    """))
    p = run_script(
        "check_stub.py", str(r.root / "tests/spec"), "--python", sys.executable, cwd=r.root,
    )
    assert p.returncode == 0, p.stdout + p.stderr
    assert "2 discriminating" in p.stdout


# ---------------------------------------------------------------------------
# trace
# ---------------------------------------------------------------------------

def test_trace_drivers_reports_the_entrypoint_reaching_the_change(make_repo):
    r = make_repo()
    r.config(code_roots=["app"], entrypoint_stems=("run",))
    r.write("app/run.py", "import app.mid\nif __name__ == '__main__':\n    pass\n")
    r.write("app/mid.py", "import app.leaf\n")
    r.write("app/leaf.py", "X = 1\n")
    base = r.commit("base")
    r.write("app/leaf.py", "X = 2\n")
    r.commit("change")
    p = run_script("trace.py", "drivers", "--base", base, cwd=r.root)
    assert p.returncode == 0, p.stderr
    assert "app/leaf.py" in p.stdout and "app/run.py" in p.stdout
    assert "import closure" in p.stdout


def test_trace_resource_splits_writers_from_readers_with_floor(make_repo):
    import json
    r = make_repo()
    r.write(".claude/spec-flow.json", json.dumps({"specGraph": {
        "artifacts": "**/spec_graph_*.yaml", "codeRoots": ["app"],
        "entrypointStems": [], "contextAliases": {}, "conceptAliases": {},
        "resources": {"log": {"writers": ["app/io.py::append_row"],
                              "readers": ["app/io.py::read_rows"]}},
    }}))
    r.write("app/io.py", "def append_row(p, row):\n    pass\n\n\ndef read_rows(p):\n    return []\n")
    r.write("app/writer.py",
            "from app.io import append_row\n\n\ndef w(d):\n    append_row(d / 'x.jsonl', {})\n")
    r.write("app/reader.py",
            "from app.io import read_rows\n\n\ndef r(d):\n    return read_rows(d / 'x.jsonl')\n")
    r.write("app/dynamic.py", "name = 'append_row'  # names the sink without importing it\n")
    r.commit("c")
    p = run_script("trace.py", "resource", "log", cwd=r.root)
    assert p.returncode == 0, p.stderr
    assert "writer app/writer.py" in p.stdout
    assert "reader app/reader.py" in p.stdout
    assert "floor" in p.stdout and "dynamic.py" in p.stdout
