"""Regression suite for the PR #674 review findings in check_gate, check_lint, and
check_claims (fixer F3).

Same house style as test_mechanical_checks: every test drives the real script via
subprocess and asserts on the observable payload — the exit code and the identity of
the element named in the finding, never exact wording. Exit contract: 0 clean, 1 the
check looked and found something, 2 it could not look (never a silent pass).
"""
from __future__ import annotations

from conftest import SPEC_GRAPH_DIR  # noqa: F401 — house import; run_script reads it
from test_mechanical_checks import run_script

# Every rule evaluated `fired: true` — no FIRED-FALSE arm, no missing-entry arm, so a
# test's exit code is decided by the trigger/answer mechanics alone.
_EVALUATED_TRUE = (
    "gate:\n  evaluated:\n"
    + "".join(f"    - {{rule: R{i}, fired: true}}\n" for i in range(7))
)

# ---------------------------------------------------------------------------
# check_gate #1 — answered() must not let a sibling facet silence a trigger
# ---------------------------------------------------------------------------

# Two design writers into `sink` fire R2 on `sink.identity`; `demands` decides whether
# the trigger is answered.
_R2_FACET_GRAPH = """\
schema_version: 1
design: "#t"
base: abc
demands:
{demands}
structure:
  axes: []
  actors:
    - {{id: w1, frame: leg, provenance: design}}
    - {{id: w2, frame: leg, provenance: design}}
  boundaries:
    - id: sink
      provenance: design
      facets:
        identity: {{sharing: serialized-append}}
        payload: {{}}
  interacts:
    - {{from: w1, to: sink, mode: write, via: fs, provenance: design}}
    - {{from: w2, to: sink, mode: write, via: fs, provenance: design}}
"""

_D_PAYLOAD = ('  - {id: d_p, kind: shape, form: test, discharged_by: test_p,\n'
              '     binds: ["sink.payload"]}')
_D_IDENTITY = ('  - {id: d_i, kind: uniqueness, form: test, discharged_by: test_i,\n'
               '     binds: ["sink.identity"]}')


def test_gate_payload_demand_does_not_answer_identity_trigger(make_repo):
    """A demand on `sink.payload` says nothing about `sink.identity` — root-only matching
    let it silence the R2 trigger (exit 0 where UNANSWERED belongs)."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _R2_FACET_GRAPH.format(demands=_D_PAYLOAD) + _EVALUATED_TRUE)
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "UNANSWERED" in p.stdout and "sink.identity" in p.stdout


def test_gate_same_facet_demand_does_answer_identity_trigger(make_repo):
    """The control: a demand binding the SAME facet answers the trigger — the fix narrows
    matching to the facet, it does not demand exact addresses everywhere."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _R2_FACET_GRAPH.format(demands=_D_IDENTITY) + _EVALUATED_TRUE)
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 0, p.stdout + p.stderr


# ---------------------------------------------------------------------------
# check_gate #2 — a design drives edge over code-provenance writers is in the delta
# ---------------------------------------------------------------------------

def test_gate_r2_fires_on_design_drives_edge_over_code_writers(make_repo):
    """rules.md's R2 trigger includes "gaining a new `drives` edge over its writers", but
    the delta test read only the boundary and the writer edges — all code-provenance
    here, so the design drives edge could never fire the rule (exit 0)."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", """\
schema_version: 1
design: "#t"
base: abc
demands: []
structure:
  axes: []
  actors:
    - {id: w1, frame: leg, provenance: code}
    - {id: drv, frame: composition, provenance: code}
  boundaries:
    - id: sink
      provenance: code
      facets:
        identity: {sharing: serialized-append}
  interacts:
    - {from: w1, to: sink, mode: write, via: fs, provenance: code}
  drives:
    - {from: drv, to: w1, multiplicity: concurrent, provenance: design}
""" + _EVALUATED_TRUE)
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "UNANSWERED" in p.stdout and "sink.identity" in p.stdout


# ---------------------------------------------------------------------------
# check_gate #3 — R4 is about the domain facet, not the `read` edge label
# ---------------------------------------------------------------------------

_R4_MODE_GRAPH = """\
schema_version: 1
design: "#t"
base: abc
demands: []
structure:
  axes: []
  actors:
{actors}
  boundaries:
    - id: knob
      provenance: design
      facets:
        domain: {{type: int, default: 30, distinguished: [0], falsy_valid: true}}
  interacts:
{interacts}
"""


def test_gate_r4_fires_when_domain_boundary_reached_only_via_invoke(make_repo):
    """Keying R4 on `mode: read` alone let an invoke-reached design domain ship its
    distinguished members unexercised — but rules.md fires on the facet gaining members."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _R4_MODE_GRAPH.format(
        actors="    - {id: caller, frame: leg, provenance: design}",
        interacts="    - {from: caller, to: knob, mode: invoke, via: call, provenance: design}",
    ) + _EVALUATED_TRUE)
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "UNANSWERED" in p.stdout and "knob.domain.distinguished[0]" in p.stdout


def test_gate_r4_fires_on_design_domain_boundary_with_no_edges(make_repo):
    """The not-yet-wired arm: a design-provenance domain boundary with NO edges into it
    still fires on the boundary alone being in the delta."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _R4_MODE_GRAPH.format(actors="    []", interacts="    []")
            + _EVALUATED_TRUE)
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "UNANSWERED" in p.stdout and "knob.domain.distinguished[0]" in p.stdout


# ---------------------------------------------------------------------------
# check_gate #5 — a scalar `binds:` is one address, not a character sequence
# ---------------------------------------------------------------------------

def test_gate_scalar_binds_is_one_address_not_per_character(make_repo):
    """`binds: "knob.domain.distinguished[0]"` (string, not list) was iterated per
    character — one bogus dangling-address finding per letter, and the real cell
    unanswered. Normalized, the single address resolves and answers the R4 trigger."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", """\
schema_version: 1
design: "#t"
base: abc
demands:
  - {id: d_cell, kind: domain-outcome, form: test, discharged_by: test_zero,
     binds: "knob.domain.distinguished[0]"}
structure:
  axes: []
  actors:
    - {id: reader, frame: leg, provenance: design}
  boundaries:
    - id: knob
      provenance: design
      facets:
        domain: {type: int, default: 30, distinguished: [0], falsy_valid: true}
  interacts:
    - {from: reader, to: knob, mode: read, via: env, provenance: design}
""" + _EVALUATED_TRUE)
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "resolves to nothing" not in p.stdout


# ---------------------------------------------------------------------------
# check_gate #6 / check_claims #15 — findings survive a later unreadable graph
# ---------------------------------------------------------------------------

def test_gate_prints_findings_before_exiting_2_on_unreadable_sibling(make_repo):
    """Returning 2 on the first unreadable graph threw away every finding the
    already-checked graphs produced: collect, keep looking, print, THEN exit 2."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g_find.yaml", _R4_MODE_GRAPH.format(
        actors="    - {id: reader, frame: leg, provenance: design}",
        interacts="    - {from: reader, to: knob, mode: read, via: env, provenance: design}",
    ) + _EVALUATED_TRUE)
    r.write("g_bad.yaml", "- the top level is a list, not a mapping\n")
    p = run_script("check_gate.py", "g_find.yaml", "g_bad.yaml", cwd=r.root)
    assert p.returncode == 2, p.stdout + p.stderr
    assert "UNANSWERED" in p.stdout and "knob.domain.distinguished[0]" in p.stdout
    assert "cannot read" in p.stderr and "g_bad.yaml" in p.stderr


# ---------------------------------------------------------------------------
# check_lint #9 — a gate entry with no demand pointer is a silencer, not a discharge
# ---------------------------------------------------------------------------

_POINTER_GRAPH = """\
schema_version: 1
design: "#t"
base: abc
demands:
  - {{id: d1, kind: behavior, form: test, discharged_by: test_a, binds: [x]}}
structure:
  boundaries:
    - {{id: x, provenance: code, facets: {{}}}}
gate:
  obligations:
    - {{rule: R2, element: x.identity, witness: w{ob_ref}}}
  pre_discharged:
    - {{rule: R4, element: x.domain, edge: "interacts(a->x)"{pd_ref}}}
"""


def test_lint_missing_discharged_by_and_by_pointers_are_findings(make_repo):
    """rules.md declares the obligation/pre_discharge shapes WITH the demand pointer; a
    bare entry passed lint while silencing check_gate's trigger."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _POINTER_GRAPH.format(ob_ref="", pd_ref=""))
    p = run_script("check_lint.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "gate.obligations" in p.stdout and "discharged_by" in p.stdout
    assert "gate.pre_discharged" in p.stdout and "`by`" in p.stdout


def test_lint_present_pointers_naming_a_real_demand_pass(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _POINTER_GRAPH.format(
        ob_ref=", discharged_by: d1", pd_ref=", by: d1"))
    p = run_script("check_lint.py", "g.yaml", cwd=r.root)
    assert p.returncode == 0, p.stdout + p.stderr


# ---------------------------------------------------------------------------
# check_claims #12 — claim ids are matched as strings, like the citations
# ---------------------------------------------------------------------------

def test_claims_int_claim_id_is_not_a_dangling_citation(make_repo):
    """`_cited` stringifies every citation while the verdict map kept int keys — so a
    YAML-bare `id: 12` made `cites: [12]` falsely dangle against its own claim."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", """\
schema_version: 1
demands:
  - {id: d1, kind: behavior, form: test, discharged_by: test_a, binds: [x], cites: [12]}
claims:
  - {id: 12, kind: behavior, claim: "x", probe: "ran it", probe_kind: executed,
     observed: "y", verdict: holds}
""")
    p = run_script("check_claims.py", "g.yaml", cwd=r.root)
    assert p.returncode == 0, p.stdout + p.stderr


# ---------------------------------------------------------------------------
# check_claims #13 — a judgment-closed hole is a spend-point: it cites or it fails
# ---------------------------------------------------------------------------

_HOLE_GRAPH = """\
schema_version: 1
{extra}gate:
  holes:
    - {{rule: R0, element: "x.access[env]", resolution: "{resolution}"{tail}}}
"""

_C_OK = """\
claims:
  - {id: c_ok, kind: reachability, claim: "x", probe: "break-attempt",
     probe_kind: executed, observed: "survived", verdict: unrefuted}
"""


def test_claims_judgment_closed_hole_without_cites_is_a_finding(make_repo):
    """A hole with a `resolution` but no `resolved_to` closed by judgment alone —
    "unreachable" closes only by citation (rules.md, 'a spend-point closes only by
    citation'), yet it passed uncited."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _HOLE_GRAPH.format(
        extra="", resolution="unreachable in this deploy", tail=""))
    p = run_script("check_claims.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "CITATION" in p.stdout and "gate.holes" in p.stdout and "cites" in p.stdout


def test_claims_hole_that_spawned_a_demand_needs_no_citation(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _HOLE_GRAPH.format(
        extra=("demands:\n"
               "  - {id: d1, kind: behavior, form: test, discharged_by: test_a, binds: [x]}\n"),
        resolution="spawned a demand", tail=", resolved_to: d1"))
    p = run_script("check_claims.py", "g.yaml", cwd=r.root)
    assert p.returncode == 0, p.stdout + p.stderr


def test_claims_judgment_closed_hole_with_probed_citation_passes(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _HOLE_GRAPH.format(
        extra=_C_OK, resolution="unreachable in this deploy", tail=", cites: [c_ok]"))
    p = run_script("check_claims.py", "g.yaml", cwd=r.root)
    assert p.returncode == 0, p.stdout + p.stderr


# ---------------------------------------------------------------------------
# check_claims #14 — no graphs matched is could-not-look, not clean
# ---------------------------------------------------------------------------

def test_claims_no_graphs_matched_exits_2(make_repo):
    """Every sibling check exits 2 when the artifacts glob matches nothing (verify.md's
    whole-toolchain contract); check_claims alone returned 0 — a pass earned by having
    no question to ask."""
    r = make_repo()
    r.config(code_roots=[], artifacts="nope/spec_graph_*.yaml")
    r.commit("base")
    p = run_script("check_claims.py", cwd=r.root)
    assert p.returncode == 2, p.stdout + p.stderr
