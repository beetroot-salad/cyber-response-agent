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

This is a measurement instrument for ``experiments/`` and its tests, not a runtime gate:
nothing in the loop calls it and no disposition depends on it.
"""
from __future__ import annotations

from pathlib import Path

from defender._io import read_jsonl_rows
from defender._run_paths import RunPaths

#: @owns GOVERNANCE_SYSTEMS — the registry systems whose being asked IS the re-ask O1 measures.
#:
#: Spelled here rather than borrowed. ``evals/oracle_golden/audit_judge.py`` ships a
#: ``STATE_SYSTEMS`` frozenset that looks like this one and is not: it carries ``threat-intel``
#: and omits ``ticket``, because it answers a different question (which systems report world
#: state) than this one does (which systems hold the authorization record a privileged action
#: has to be squared with). Importing it would get both ends wrong.
GOVERNANCE_SYSTEMS: frozenset[str] = frozenset({"cmdb", "change-mgmt", "identity", "ticket"})


def _param_values(params: object) -> list[str]:
    """Every STRING leaf of a ``params`` mapping, keys excluded, containers walked.

    Three decisions live here, none of which the design settles; each is pinned by a test in
    ``tests/test_986_governance_reask.py``.

    KEYS ARE NOT VALUES. ``{"db-1": "lookup"}`` names a parameter for the machine; it does not
    ask about it. The design says "among its ``params`` values" and this is that word read
    strictly, which also rules out the ``json.dumps(params)`` shortcut.

    CONTAINERS ARE WALKED. A change-mgmt query that filters on a list of CIs, or carries a
    structured filter object, asks about every host it names, and reading only the top level
    would score those runs as misses. The recursion widens what counts as a VALUE; it never
    touches what counts as a MATCH.

    NON-STRINGS ARE NOT NAMES. ``params`` values are not all strings — ``limit`` is an int on
    every paginated query — and a resolved machine name always arrives as one. Coercing leaves
    to text buys nothing and costs a False positive for the machine named ``1`` on every
    paginated governance call.

    A ``params`` that is not a mapping has no values at all: a bare string there is malformed
    telemetry, and searching it would be the row-grep this module exists to refuse, one cell in.
    """
    if not isinstance(params, dict):
        return []
    out: list[str] = []
    stack: list[object] = list(params.values())
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
    return out


def asked_governance_about(run_dir: Path, name: str) -> bool:
    """@owns the governance-re-ask verdict — the one place a run dir becomes O1's boolean.

    Every consumer (the unit tests, an ``experiments/`` harness scoring a trial batch) calls
    this rather than re-deriving the predicate, because two spellings of "did the run ask about
    this machine" that quietly disagree would put two different baselines in two different
    write-ups of the same nine runs.

    The comparison is WHOLE-VALUE and CASE-INSENSITIVE, both assumptions rather than
    derivations. Whole-value because a substring rule reads "asked CMDB about db-11" as "asked
    about db-1" — the coarse/fine confusion #986 exists to refuse, wearing a different hat.
    Case-insensitive because a CMDB record spelled ``DB-1`` is the same machine, and scoring a
    real re-ask as a miss would understate the rate the experiment measures.

    Never raises on a run dir. A run that died before its first gather writes no log; a live
    tree's last line can be torn mid-append (which is why the read goes through the tolerant
    ``read_jsonl_rows`` and not a hand-rolled loop); a log can be unreadable outright. All three
    are False, not an exception, because the caller is scoring a BATCH of runs and one bad tree
    must not take the batch down. The ``OSError`` catch follows the decision the neighbouring
    reader of this same file already made (``record_query.lead_rows``: "reading this table must
    never be what starts crashing the query tool") — ``read_jsonl_rows`` screens a missing path
    and a non-file, and lets a permission fault through.
    """
    wanted = name.strip().casefold()
    if not wanted:
        # An unresolved name must not report that governance was asked — otherwise the
        # cheapest possible harness bug reads as a perfect score.
        return False
    try:
        rows = read_jsonl_rows(RunPaths(Path(run_dir)).executed_queries)
    except OSError:
        return False
    for row in rows:
        if row.get("system") not in GOVERNANCE_SYSTEMS:
            continue
        if any(value.strip().casefold() == wanted for value in _param_values(row.get("params"))):
            return True
    return False
