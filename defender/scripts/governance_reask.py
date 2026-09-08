"""#986 M4 — did this run put the RESOLVED machine to a governance system?

O1's mechanical oracle. When a lead resolves the machine the alerted privileged action
actually ran on — the container on the alerted host — the run is supposed to ask the
governance systems about *that* machine before it closes. The design settles the measurement
rather than leaving it to a reader:

    true iff some row of ``executed_queries.jsonl`` whose ``system`` is one of ``cmdb``,
    ``change-mgmt``, ``identity``, ``ticket`` carries the resolved name among its ``params``
    VALUES.

Baseline over the nine runs the design was written from: 0/9 for the resolved container,
while the coarser host named in the alert envelope appears 5-11 times per run. THAT PAIRING IS
THE WHOLE POINT — governance *was* asked, about the coarse subject — and it is why this module
reads the ``params`` mapping rather than searching the row. A whole-row string search scores a
shell line that merely mentions the container as a question the run never asked — in the
flattering direction, on the instrument a live-trial rate is computed with. An oracle that can
be fooled is worse than no oracle.

THE ROW SHAPE COMES FROM ``learning.lead_repository.load_queries``, not from a second parse of
the file. ``defender/CLAUDE.md`` names that module THE read/join surface for the two tables —
"consumers never re-parse the artifacts" — and the tolerance a re-parse would have to
hand-write is already there and already tested: a missing or unreadable log is ``[]``, a torn
physical line is dropped, a row whose ``system`` cell is not a string coarsens to ``""``
instead of being spent as a set key, and a non-mapping ``params`` coarsens to ``{}``.

WHAT THIS ORACLE STILL CANNOT SEPARATE, stated as a limit rather than left to be discovered.
A governance row is counted whether or not the call reached the system. ``query_tool`` writes
a row for calls that never executed — the repeat guard's trip (``∅.repeat-trip``), the three
above-guard writers (``∅.above-repeat-guard``: the schema rejection, the adapter-load fault
and the unresolvable verb), and ``_screen``'s param/traversal/self-ticket refusal, which keeps
an ORDINARY ``query_id`` — and each keeps ``system`` and ``params`` verbatim. So a run of
twelve REFUSED cmdb calls about the container scores 12/12. That is M4's letter and this
module implements it, but it is a design call and not a data limit: the row carries the two
fields that separate the cases, and ``load_queries`` hands both over already typed —
``QueryRow.is_sentinel`` (the writer's own ``∅.`` predicate) covers the four sentinel writers,
and ``exit_code == 0`` — ``query_tool``'s own spelling of "what actually executed" — covers
``_screen``'s refusal too. Flipping the reading is one predicate here, and
``test_a_refused_governance_call_counts_as_an_ask`` is the test that has to change with it.
(A POLICY DENIAL is not in that set: ``_grant_check``'s ``DENIED`` branch logs to
``policy_denials.jsonl`` and returns without writing a query row at all.)

This is a measurement instrument for ``experiments/`` and its tests, not a runtime gate:
nothing in the loop calls it and no disposition depends on it.
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from defender._text import as_str
from defender.learning.lead_repository import load_queries

#: The registry systems whose being asked IS the re-ask O1 measures. Claimed as owned in
#: :func:`asked_governance_about`'s docstring, which is where `lint_unowned_field` reads.
#:
#: Spelled here rather than borrowed. ``evals/oracle_golden/audit_judge.py`` ships a
#: ``STATE_SYSTEMS`` frozenset that looks like this one and is not: it carries ``threat-intel``
#: and omits ``ticket``, because it answers a different question (which systems report world
#: state) than this one does (which systems hold the authorization record a privileged action
#: has to be squared with). Importing it would get both ends wrong.
#:
#: NOT the only spelling in the repo today: ``experiments/auditor-role-986/analyze.py`` carries
#: an identical four-member tuple under the same name for the same issue's LLM-judge arm. That
#: file is outside every gate's scanned tree, so nothing mechanical will notice if the two
#: drift; the harness should import this one.
GOVERNANCE_SYSTEMS: frozenset[str] = frozenset({"cmdb", "change-mgmt", "identity", "ticket"})


def _param_values(params: object) -> Iterator[str]:
    """Every STRING leaf of a ``params`` value, keys excluded, containers walked.

    Three decisions live here, none of which the design settles; each is pinned by a test in
    ``tests/test_986_governance_reask.py``.

    KEYS ARE NOT VALUES. ``{"db-1": "lookup"}`` names a parameter for the machine; it does not
    ask about it. The design says "among its ``params`` values" and this is that word read
    strictly, which also rules out the ``json.dumps(params)`` shortcut.

    CONTAINERS ARE WALKED, at every depth including the top. A change-mgmt query that filters
    on a list of CIs, or carries a structured filter object, asks about every host it names,
    and reading only the top level would score those runs as misses. The recursion widens what
    counts as a VALUE; it never touches what counts as a MATCH. A scalar (or a bare string —
    malformed telemetry, and searching it would be the row-grep this module exists to refuse,
    one cell in) has no values at all. Through :func:`asked_governance_about` the top level is
    always a mapping anyway — ``load_queries`` coerces a non-dict ``params`` cell to ``{}``
    before this sees it — so the top-level container case is the helper's own contract rather
    than a shape a run dir can present.

    NON-STRINGS ARE NOT NAMES. ``params`` values are not all strings — ``limit`` is an int on
    every paginated query — and a resolved machine name always arrives as one. Coercing leaves
    to text buys nothing and costs a False positive for the machine named ``1`` on every
    paginated governance call.

    A GENERATOR, so the caller's ``any(...)`` stops at the first leaf that matches instead of
    materialising every CI name on a bulk change-mgmt filter first.
    """
    stack: list[object] = []
    if isinstance(params, dict):
        stack.extend(params.values())
    elif isinstance(params, (list, tuple)):
        stack.extend(params)
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)


def asked_governance_about(run_dir: Path, name: str) -> bool:
    """@owns GOVERNANCE_SYSTEMS, and the verdict it decides — the one place a run dir becomes
    O1's boolean.

    Every consumer (the unit tests, an ``experiments/`` harness scoring a trial batch) should
    call this rather than re-deriving the predicate, because two spellings of "did the run ask
    about this machine" that quietly disagree would put two different baselines in two
    different write-ups of the same nine runs.

    The comparison is WHOLE-VALUE and CASE-INSENSITIVE, both assumptions rather than
    derivations. Whole-value because a substring rule reads "asked CMDB about db-11" as "asked
    about db-1" — the coarse/fine confusion #986 exists to refuse, wearing a different hat.
    Case-insensitive because a CMDB record spelled ``DB-1`` is the same machine, and scoring a
    real re-ask as a miss would understate the rate the experiment measures. BOTH SIDES ARE
    ALSO TRIMMED — a fifth assumption beside the design's four, pinned by
    `test_both_the_subject_and_the_value_are_trimmed_before_comparison`. On the name because a
    subject read out of a record cell can carry the record's own padding; on the value because
    `"db-1 "` is the same machine, which widens the whole-value rule by that character class
    and is therefore said out loud. The SYSTEM cell is matched exactly, and deliberately not
    folded: the registry resolves a system name
    case-sensitively, so a row spelling ``CMDB`` is a call that never resolved and never ran.

    Never raises on a run dir, nor on a degenerate name. A run that died before its first
    gather writes no log; a live tree's last line can be torn mid-append; a log can be
    unreadable outright; a cell can hold a shape its column does not declare. All of those are
    False rather than an exception — the caller is scoring a BATCH of runs and one bad tree
    must not take the batch down — and all of them are ``load_queries``' answer, not a
    tolerance re-derived here. An unresolved subject is False for a reason of its own: a name
    that is absent or trims to nothing must not report that governance was asked, or the
    cheapest possible harness bug reads as a perfect score.
    """
    wanted = as_str(name).strip().casefold()
    if not wanted:
        return False
    for row in load_queries(Path(run_dir)):
        if row.system not in GOVERNANCE_SYSTEMS:
            continue
        if any(value.strip().casefold() == wanted for value in _param_values(row.params)):
            return True
    return False
