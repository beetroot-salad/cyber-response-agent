"""#869 M3/O2/U3 — the queries-table row names the system the call was dispatched to."""
from __future__ import annotations

from defender.learning.leads.draft_synthesis import (
    _draft_basename,
    _draft_candidate_segments,
)
from defender.runtime.query_tool import resolve_query_id


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


