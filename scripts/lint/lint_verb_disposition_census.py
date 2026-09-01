#!/usr/bin/env python3
"""Verb-disposition census — every verb the tree declares has a decision, and every decision
names a verb the tree declares.

WHAT THIS CLOSES (#995). The gather grant was a hand-written list of `(system, verb)` pairs,
and the thing that looked like it guarded that list compared it against a SECOND hand-written
copy in the test suite. Two copies agreeing catches one of them being edited wrongly. It
cannot catch a system missing from both — which is exactly the reported defect: a system
connected by `/connect`, absent from the grant, silently unreachable, and reporting its real
verbs as if they were typos.

So the check that matters is not "do the two lists agree" but "does the authored table have an
opinion about everything that exists". This gate supplies the walked census to
`verb_dispositions.census_gaps` and fails on residue in either direction.

WHY THIS IS NOT "DERIVE THE GRANT FROM THE ADAPTERS". That repair would mean dropping an
adapter file into the tree grants it access. Nothing here writes a grant; the gate only
refuses to let a decision go unmade. A new system still grants itself nothing — it just can no
longer be ungranted by accident rather than on the record.

NOT BASELINE-RATCHETED, unlike most gates here. A ratchet exists to let a pre-existing
population of findings be paid down over time; this gate's finding population is empty by
construction the moment it lands, and its whole value is that the NEXT system cannot slip
through. A baseline would be a list of systems allowed to stay silently unreachable, which is
the defect wearing the fix's clothes. The residue this gate does admit — a verb granted to
nobody — lives in the table itself with a written reason, where a reviewer reads it beside the
grant it qualifies.

Run: defender/.venv/bin/python scripts/lint/lint_verb_disposition_census.py [--root <repo>]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# The resolver and the loader are IMPORTED, never reimplemented. A gate that re-derived "which
# systems exist" with its own glob would be a fifth hand-maintained answer to the question this
# gate exists to stop having several answers to — and `lint_shared_oracle` refuses that shape
# for tests for the same reason it is wrong here.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender.learning.leads.declared_systems import declared_systems  # noqa: E402
from defender.learning.leads.lead_extraction import LeadAuthorError  # noqa: E402
from defender.runtime.verb_dispositions import (  # noqa: E402
    DispositionError,
    census_gaps,
    dispositions_path,
    load_dispositions,
)
from defender.runtime.verbs import declared_verb_names  # noqa: E402


def _walk(defender_dir: Path, systems: frozenset[str]) -> dict[str, frozenset[str]]:
    adapters = defender_dir / "scripts" / "adapters"
    return {s: declared_verb_names(adapters, s) for s in sorted(systems)}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(REPO_ROOT), help="repo root to check")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    defender_dir = root / "defender"

    # Exit 2, not 1, when the gate could not RUN. An unreadable source or an unloadable table
    # means the census was never taken, and a gate that prints "0 findings" because it scanned
    # nothing is categorically not clean (#618/#621/#652).
    try:
        systems = declared_systems(root)
    except LeadAuthorError as e:
        print(f"lint_verb_disposition_census: cannot resolve systems: {e}", file=sys.stderr)
        return 2
    try:
        rows = load_dispositions(dispositions_path(defender_dir))
    except DispositionError as e:
        print(f"lint_verb_disposition_census: {e}", file=sys.stderr)
        return 2

    gaps = census_gaps(_walk(defender_dir, systems), rows)
    if not gaps:
        print(
            f"lint_verb_disposition_census: clean — {len(rows)} dispositions cover "
            f"{len(systems)} system(s) with no residue."
        )
        return 0

    for system, verb in gaps.undecided:
        print(
            f"{system}.{verb}: declared by an adapter, decided by nobody. Add a row to "
            f"{dispositions_path(defender_dir).relative_to(root)} granting it to a role, or "
            "`roles: []` with a reason if it is deliberately reachable by no one."
        )
    for system, verb in gaps.phantom:
        print(
            f"{system}.{verb}: the table decides a verb no adapter declares. Remove the row, "
            "or restore the verb."
        )
    for system, verb in gaps.unreasoned:
        print(f"{system}.{verb}: granted to nobody with no reason given.")
    print(
        f"lint_verb_disposition_census: {len(gaps.undecided)} undecided, "
        f"{len(gaps.phantom)} phantom, {len(gaps.unreasoned)} unreasoned."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
