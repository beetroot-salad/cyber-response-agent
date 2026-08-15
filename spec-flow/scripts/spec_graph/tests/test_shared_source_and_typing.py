"""R7 (shared source) and the claim-typing pass — the two mechanical nets added for the
stale-mirror escape class and the mis-typed-claim hole.

House style: drive the real script via subprocess, assert on the exit code and the identity
of the element named, never on wording. Exit contract: 0 clean, 1 looked and found, 2 could
not look.

Both checks answer a shipped bug rather than a hypothesis. R7's is the value honored at one
site and mirrored, stale, at another — a shape that adds and removes nothing, so every
add/remove rule stays quiet and each reader is correct read alone. The typing pass's is a
claim that predicted what every persisted record holds, typed `referential`, and closed by
reading the code: the instrument table was satisfied because the table trusts the kind its
author declared.
"""
from __future__ import annotations

from conftest import SPEC_GRAPH_DIR  # noqa: F401 — house import; run_script reads it
from test_mechanical_checks import run_script

_EVALUATED_TRUE = (
    "gate:\n  evaluated:\n"
    + "".join(f"    - {{rule: R{i}, fired: true}}\n" for i in range(8))
)

# `ceiling` is read by three actors. `provenance` on each read edge is the delta membership
# the rule keys on, so a fixture selects the moved/unmoved split by writing those three
# values — the same slot the rest of the gate scopes its delta with.
_SHARED_SOURCE = """\
schema_version: 1
design: "#t"
base: abc
demands:
{demands}
structure:
  axes: []
  actors:
    - {{id: raiser,    frame: leg, provenance: design}}
    - {{id: mirror_a,  frame: leg, provenance: {a_prov}}}
    - {{id: mirror_b,  frame: leg, provenance: {b_prov}}}
  boundaries:
    - {{id: ceiling, provenance: {b_ceiling}, facets: {{}}}}
  interacts:
    - {{from: raiser,   to: ceiling, mode: read, via: api, provenance: design}}
    - {{from: mirror_a, to: ceiling, mode: read, via: api, provenance: {a_prov}}}
    - {{from: mirror_b, to: ceiling, mode: read, via: api, provenance: {b_prov}}}
  drives: []
"""

_NO_DEMANDS = "  []"
# One coherence demand naming BOTH unmoved reader edges — the shape that legitimately
# discharges R7, and the reason the obligation is expressible without a schema change.
_BOTH_EDGES = """\
  - {id: coherent, kind: behavior, form: test, discharged_by: test_coherent,
     binds: ["interacts(mirror_a->ceiling)", "interacts(mirror_b->ceiling)"]}
"""
# A demand at the boundary's own altitude — "two of the three moved" reads as discharged
# unless the obligation is pinned per reader.
_BOUNDARY_ONLY = """\
  - {id: coarse, kind: behavior, form: test, discharged_by: test_coarse,
     binds: ["ceiling"]}
"""


def _graph(demands: str, *, a_prov: str = "code", b_prov: str = "code",
           b_ceiling: str = "design") -> str:
    # The evaluated block is appended, never formatted: its `{rule: R0, ...}` braces are
    # YAML flow mappings, and str.format reads them as replacement fields.
    return _SHARED_SOURCE.format(
        demands=demands, a_prov=a_prov, b_prov=b_prov, b_ceiling=b_ceiling
    ) + _EVALUATED_TRUE


def test_r7_fires_per_unmoved_reader_of_a_changed_source(make_repo):
    """The escape itself: a source in the delta, two readers left on the old reading."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _graph(_NO_DEMANDS))
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    # One finding per unmoved reader, each naming that reader's own edge.
    assert "interacts(mirror_a->ceiling)" in p.stdout
    assert "interacts(mirror_b->ceiling)" in p.stdout


def test_r7_is_silent_when_every_reader_moves_with_the_source(make_repo):
    """No unmoved side, no drift: the rule is differential, not a multi-reader census."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _graph(_NO_DEMANDS, a_prov="design", b_prov="design"))
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert "R7" not in p.stdout


def test_r7_is_silent_when_nothing_touches_the_source(make_repo):
    """Three readers that all predate the change are just three readers."""
    r = make_repo()
    r.config(code_roots=[])
    graph = _graph(_NO_DEMANDS, b_ceiling="code").replace(
        "{from: raiser,   to: ceiling, mode: read, via: api, provenance: design}",
        "{from: raiser,   to: ceiling, mode: read, via: api, provenance: code}",
    )
    r.write("g.yaml", graph)
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert "R7" not in p.stdout


def test_r7_discharges_only_on_a_demand_that_names_each_reader_edge(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _graph(_BOTH_EDGES))
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert "R7" not in p.stdout


def test_a_boundary_wide_demand_does_not_discharge_a_per_reader_obligation(make_repo):
    """The altitude collapse the rule exists to catch: a demand on the shared value itself
    says nothing about which of its readers were driven, so it must not silence R7."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _graph(_BOUNDARY_ONLY))
    p = run_script("check_gate.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    assert "interacts(mirror_a->ceiling)" in p.stdout


# ---------------------------------------------------------------------------
# check_claims — the typing pass under the instrument table
# ---------------------------------------------------------------------------

_CLAIMS = """\
schema_version: 1
design: "#t"
base: abc
demands: []
structure: {{axes: [], actors: [], boundaries: [], interacts: [], drives: []}}
claims:
  - {{id: C1, kind: {kind}, claim: "{claim}", probe: "p", probe_kind: {pk},
     observed: "o", verdict: holds}}
"""


def _claims(kind: str, claim: str, pk: str) -> str:
    return _CLAIMS.format(kind=kind, claim=claim, pk=pk) + _EVALUATED_TRUE


def test_a_runtime_prediction_may_not_be_typed_referential(make_repo):
    """The shipped shape: a prediction about what the code does, filed under a kind whose
    instrument is a read, so the instrument table passes it."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _claims(
        "referential", "the writer silently drops a record when the round is unset", "read"
    ))
    p = run_script("check_claims.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    assert "MISTYPED" in p.stdout and "C1" in p.stdout


def test_a_census_that_predicts_a_failure_is_mistyped(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _claims(
        "census", "these are all four call sites, and each fails closed on a bad key", "search"
    ))
    p = run_script("check_claims.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    assert "MISTYPED" in p.stdout


def test_a_structural_claim_is_left_alone(make_repo):
    """The check flags grammar, not judgment — an existence claim closed on a read is
    exactly what `referential` is for, and a false positive here would push authors to
    retype honest claims."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _claims(
        "referential", "resolve_store_path is defined in store.py with a base_dir parameter",
        "read",
    ))
    p = run_script("check_claims.py", "g.yaml", cwd=r.root)
    assert p.returncode == 0


def test_running_the_probe_anyway_is_never_a_typing_finding(make_repo):
    """A claim typed inspectable but closed by execution used the stronger instrument;
    a MISTYPED finding here would penalise the direction this check exists to push.

    Scoped to the typing pass on purpose: the pre-existing instrument table treats its
    kind→probe_kind mapping as exact, so `referential` + `executed` is its own INSTRUMENT
    finding. That is a separate rule with a separate history, and the assertion here must
    not quietly depend on it either way."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _claims(
        "referential", "the helper silently drops malformed rows", "executed"
    ))
    p = run_script("check_claims.py", "g.yaml", cwd=r.root)
    assert "MISTYPED" not in p.stdout


# ---------------------------------------------------------------------------
# check_claims — the probe-corpus pass (#869: an executed probe over ASCII only)
# ---------------------------------------------------------------------------

_CORPUS = """\
schema_version: 1
design: "#t"
base: abc
demands: []
structure: {{axes: [], actors: [], boundaries: [], interacts: [], drives: []}}
claims:
  - {{id: X2, kind: primitive, claim: "the marker read answers from HEAD",
     probe: "{probe}", probe_kind: executed, observed: "o", verdict: holds{alphabet}}}
"""

_FULL_ALPHABET = (
    ",\n     alphabet: {ascii: 'elastic', non-ascii: 'café — C-quoted', "
    "space: 'my sys — torn by split', cwd: 'root and a subdir'}"
)


def _corpus(probe: str, alphabet: str = "") -> str:
    return _CORPUS.format(probe=probe, alphabet=alphabet) + _EVALUATED_TRUE


def test_a_name_enumerating_probe_without_an_alphabet_is_a_finding(make_repo):
    """The shipped shape: `git ls-tree -r --name-only HEAD` over a planted ASCII tree, its
    output transcribed into the reader. Executed, correctly typed, correctly instrumented —
    and blind to every name class the fixture did not contain."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _corpus("ran `git ls-tree -r --name-only HEAD -- defender/skills/`"))
    p = run_script("check_claims.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    assert "CORPUS" in p.stdout and "X2" in p.stdout


def test_the_alphabet_closes_the_finding(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _corpus(
        "ran `git ls-tree -r --name-only HEAD -- defender/skills/`", _FULL_ALPHABET
    ))
    p = run_script("check_claims.py", "g.yaml", cwd=r.root)
    assert "CORPUS" not in p.stdout


def test_a_missing_class_is_named_rather_than_passed(make_repo):
    """Partial credit is the failure mode this pass exists to refuse — #869's probe would
    have honestly filled in `ascii` and stopped there."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _corpus(
        "ran `git ls-tree -r --name-only HEAD`",
        ",\n     alphabet: {ascii: 'elastic', non-ascii: 'café', space: 'my sys'}",
    ))
    p = run_script("check_claims.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    assert "CORPUS" in p.stdout and "cwd" in p.stdout


def test_a_blank_class_does_not_count_as_an_answer(make_repo):
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _corpus(
        "ran `git ls-tree -r --name-only HEAD`",
        ",\n     alphabet: {ascii: 'elastic', non-ascii: '', space: 'my sys', cwd: 'root'}",
    ))
    p = run_script("check_claims.py", "g.yaml", cwd=r.root)
    assert p.returncode == 1
    assert "CORPUS" in p.stdout and "non-ascii" in p.stdout


def test_a_probe_that_enumerates_nothing_owes_no_alphabet(make_repo):
    """The pass must stay narrow: an executed probe over a value the probe itself constructs
    has its input written down already, and demanding a name corpus of it would make the
    field paperwork everyone learns to fill in blind."""
    r = make_repo()
    r.config(code_roots=[])
    r.write("g.yaml", _corpus("called `resolve('elastic.auth-history')` and read the return"))
    p = run_script("check_claims.py", "g.yaml", cwd=r.root)
    assert "CORPUS" not in p.stdout
