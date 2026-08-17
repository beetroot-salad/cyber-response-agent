"""#869 M3/O2/U3 — the queries-table row names the system the call was dispatched to.

Every test here is one demand of `spec-flow/specs/spec_graph_869.yaml`, named after that
demand's `discharged_by` pointer and carrying its prose in its docstring. The seam contract
lives in `defender/tests/_declared869.py`; the SINK half of M3 — what a real granted call
actually records — is `test_869_queries_row.py`, driven end to end.

`resolve_query_id` is the writer-side screen, and it needs no membership set: M3 is a pure
SHAPE rule (the #855 posture), which is why it can close the one reachable instance
(C12/C12r/G3) at the writer rather than depending on any tree.
"""
from __future__ import annotations

from defender.learning.leads import pitfalls_curator
from defender.learning.leads.draft_synthesis import (
    _draft_basename,
    _draft_candidate_segments,
)
from defender.runtime.query_tool import resolve_query_id
from defender.tests._declared869 import pitfall_row


def test_resolve_query_id_refuses_a_foreign_prefix():
    """A model-supplied `query_id` whose prefix is not the call's own system is REFUSED and
    falls back to `{system}.{verb}` — the value the queries-table row then carries.

    This is the mechanism that closes the ONE reachable instance of the whole issue
    (C12/C12r/G3, reproduced at this base): `resolve_query_id('elastic', 'esql',
    'fakesys.hunt-creds')` returns it VERBATIM today, and the host then mints
    `gather/queries/fakesys/_draft/hunt-creds.md` from it. Refused exactly like a reserved or
    traversal-bearing id — a shape rule at the writer, with no registry lookup.
    """
    assert resolve_query_id("elastic", "esql", "fakesys.hunt-creds") == "elastic.esql"
    # The two shapes that are already refused, so the new rule joins a screen rather than
    # replacing one: a reserved sentinel prefix and a traversal-bearing id.
    assert resolve_query_id("elastic", "esql", "∅.bash-shim") == "elastic.esql"
    assert resolve_query_id("elastic", "esql", "../x") == "elastic.esql"


def test_resolve_query_id_keeps_a_matching_prefix():
    """The rule refuses a DISAGREEING prefix, not model-supplied ids as a class.

    `qid_foreign_prefix_refused`'s positive control on the same address: an id whose prefix IS
    the dispatched system survives verbatim, so the coined-id lane that feeds draft synthesis
    keeps working. A screen that refused everything would satisfy the negative and break the
    feature.
    """
    assert resolve_query_id("elastic", "esql", "elastic.hunt-creds") == "elastic.hunt-creds"
    assert resolve_query_id("cmdb", "get-host", "cmdb.crown-jewels") == "cmdb.crown-jewels"


def test_refused_query_id_lands_on_the_untagged_value():
    """A refused id lands on exactly the value an UNTAGGED call already records — `{system}.
    {verb}`, or `{system}.ad-hoc` when the call names no verb.

    C18/G10, re-executed at this base. This is why enforcement cannot strand a legitimate
    call: the fallback is not a new value anyone downstream has to learn, it is the one draft
    synthesis already treats as untagged, and the two are shown here to be the same string.
    """
    untagged = resolve_query_id("elastic", "esql", None)
    assert untagged == "elastic.esql"
    assert resolve_query_id("elastic", "esql", "fakesys.hunt-creds") == untagged

    no_verb = resolve_query_id("elastic", "", None)
    assert no_verb == "elastic.ad-hoc"
    assert resolve_query_id("elastic", "", "fakesys.hunt-creds") == no_verb


def test_resolve_query_id_enforces_the_whole_schema_shape():
    """M3 enforces the WHOLE `{system}.{kebab-name}` shape, not only the prefix (FK-7, §7).

    Three values pass a prefix-only rule while violating the schema `defender/CLAUDE.md`
    states, and each must fall back:

    * `'elastic'` — no separator at all. D1, executed at this base: it passes VERBATIM today.
    * `'elastic.'` — an empty remainder.
    * `'elastic.foo.bar'` — whose remainder `_draft_candidate_segments`' `split('.', 1)` turns
      into the kebab `'foo.bar'`, a SECOND unvalidated model-supplied path component at the
      host-side draft writer.

    Closing D1 is the point: a prefix-only rule leaves a model-supplied string in the filename
    position of a `mkdir` + `write_text`, which is the shape of the very finding this issue
    exists to close, one field over. `id_prefix_rule_admits_the_committed_corpus` is the
    positive control over the committed corpus; the well-formed coined id below is the one on
    this address.

    Since #917's review the writer no longer spends ANY part of the id as a path component —
    the basename is `sha256(query_id)`, so the filename position holds a hex digest whatever
    the model coined. That is a second line, not a replacement for this one: FK-7 is still what
    keeps a malformed id out of `covers:`, out of the dedup, and off the author's desk, and
    this test is about FK-7. The third value's consequence is asserted below as it now stands
    rather than as it stood — a refused id yields a derived name, and the fallback yields no
    candidate at all.
    """
    assert resolve_query_id("elastic", "esql", "elastic") == "elastic.esql"
    assert resolve_query_id("elastic", "esql", "elastic.") == "elastic.esql"
    assert resolve_query_id("elastic", "esql", "elastic.foo.bar") == "elastic.esql"

    # What the third one reaches the draft writer as, and what it spends instead.
    # `row_system="elastic"` throughout: these ids all claim the system the row really reached,
    # so #901's id/row agreement check admits them and the shape rule is the only thing under
    # test here.
    #
    # `'foo.bar'` used to come straight back as the basename — the second model-supplied path
    # component the docstring names. It is a digest now, so the assertion is that NOTHING of the
    # coined string reaches the path: the segment is derived, and `.` is not in its alphabet.
    system, basename = _draft_candidate_segments(
        "elastic.foo.bar", "esql", set(), row_system="elastic")
    assert system == "elastic"
    assert basename == _draft_basename("elastic.foo.bar")
    assert "foo" not in basename
    assert "." not in basename
    assert _draft_candidate_segments(
        resolve_query_id("elastic", "esql", "elastic.foo.bar"), "esql", set(),
        row_system="elastic",
    ) is None

    # The control on the same address: a well-formed coined id still survives.
    assert resolve_query_id("elastic", "esql", "elastic.hunt-creds") == "elastic.hunt-creds"


def test_the_prefix_comparison_folds_nothing():
    """The prefix comparison is EXACT CODEPOINT EQUALITY — no case folding, no NFC, no
    confusable mapping (FK-6, §7, pinned as REJECTED so the crossing is stated either way).

    A `query_id` prefixed `Elastic.` or carrying a Cyrillic `е` on a call dispatched to
    `elastic` is REFUSED — it falls back — never folded onto the real system. Failing closed
    is the whole reason: folding would introduce a second name space every gate would then
    have to agree on.

    AND THE WHITESPACE ASYMMETRY IS STATED, NOT FIXED (J5): `_build_pitfalls_handoffs` strips
    whitespace from a queued row's `system` BEFORE the predicate, so `'elastic '` is admitted
    at site 1 while `'Elastic'` is refused everywhere. Both halves are asserted in one test so
    the asymmetry is a recorded decision rather than an implementation accident a later reader
    tidies away.
    """
    cyrillic = "еlastic.hunt-creds"
    assert cyrillic != "elastic.hunt-creds"
    assert resolve_query_id("elastic", "esql", "Elastic.hunt-creds") == "elastic.esql"
    assert resolve_query_id("elastic", "esql", cyrillic) == "elastic.esql"

    systems = frozenset({"elastic"})
    padded = pitfalls_curator._build_pitfalls_handoffs(
        [pitfall_row("r:0", "elastic ")], systems=systems)
    assert [h["system"] for h in padded] == ["elastic"]
    assert padded[0]["execution_md_path"] == "defender/skills/elastic/execution.md"

    assert pitfalls_curator._build_pitfalls_handoffs(
        [pitfall_row("r:1", "Elastic")], systems=systems) == []
