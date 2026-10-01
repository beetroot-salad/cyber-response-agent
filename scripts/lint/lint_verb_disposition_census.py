#!/usr/bin/env python3
"""Verb-disposition census: every verb the tree declares has a decision, and every decision
names a verb the tree declares.

Comparing a hand-written grant against a second hand-written copy catches one copy being edited
wrongly, but not a system missing from both — which leaves a connected system silently
unreachable. The check that matters is whether the authored table has an opinion about
everything that exists: this gate supplies the walked census to
`verb_dispositions.census_gaps` and fails on residue in either direction.

It does not derive the grant from the adapters: then dropping an adapter file into the tree
would grant it access. Nothing here writes a grant; a new system still grants itself nothing,
but cannot be left ungranted by accident, only on the record.

Not baseline-ratcheted: the finding population is empty by construction, and a baseline would
be a list of systems allowed to stay silently unreachable. The residue it does admit — a verb
granted to nobody — lives in the table with a written reason, beside the grant it qualifies.

Run: defender/.venv/bin/python scripts/lint/lint_verb_disposition_census.py [--root <repo>]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# The census, the folder rules and the loader are imported, never reimplemented: a gate
# re-deriving "which systems exist" with its own glob would be one more hand-maintained answer
# to the question this gate exists to unify — and `tenant.py check` asks the same one.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender import _tenant  # noqa: E402
from defender._tenant_census import (  # noqa: E402
    CensusUnavailable,
    table_findings,
    take_census,
)
from defender._tenants import template_dir  # noqa: E402
from defender.runtime.verb_dispositions import (  # noqa: E402
    DispositionError,
    dispositions_path,
    grant_for,
    load_dispositions,
)

#: The product repo's own knowledge folders this gate walks: the template `tenant.py scaffold`
#: copies, and the frozen fixture the tests run as. A real tenant's folder lives in its own
#: repo, checked there by `tenant.py check --folder`; no tenants root is walked.
FIXTURE_DIRNAME = "tenant-fixture"


def _folders(root: Path) -> list[tuple[str, Path]]:
    """Every knowledge folder the gate checks, as `(name, folder)`: the template, then the
    fixture."""
    template = template_dir(root)
    return [(template.name, template), (FIXTURE_DIRNAME, template.parent / FIXTURE_DIRNAME)]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(REPO_ROOT), help="repo root to check")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()

    # Exit 2, not 1, when the census was never taken (unreadable source or table).
    try:
        census = take_census(root / "defender", root)
    except CensusUnavailable as blind:
        print(f"lint_verb_disposition_census: {blind}", file=sys.stderr)
        return 2

    # The template and the fixture. Grants describe the shared adapters, so each folder's table
    # must be total over the one walked census, through the same folder rules and the same
    # census `tenant.py check --folder` applies to a tenant's own repo.
    worst = 0
    for name, folder in _folders(root):
        try:
            _tenant.check_knowledge_folder(folder, tenant_id=None)
        except _tenant.TenantRefused as refusal:
            print(f"lint_verb_disposition_census: {name}: a run would refuse this folder: "
                  f"{refusal}", file=sys.stderr)
            worst = 2
            continue
        settings = folder / "settings"
        try:
            findings = table_findings(settings, census)
        except DispositionError as e:
            print(f"lint_verb_disposition_census: {name}: {e}", file=sys.stderr)
            worst = 2
            continue
        lines = findings.lines(dispositions_path(settings).relative_to(root))
        if not lines:
            rows = load_dispositions(dispositions_path(settings))
            print(
                f"lint_verb_disposition_census: {name}: clean — {findings.rows} dispositions "
                f"cover {len(census.systems)} system(s) with no residue "
                f"({len(grant_for('gather', rows).entries)} granted to gather)."
            )
            continue
        worst = max(worst, 1)
        for line in lines:
            print(f"{name}: {line}")
        gaps = findings.gaps
        print(
            f"lint_verb_disposition_census: {name}: {len(gaps.undecided)} undecided, "
            f"{len(gaps.phantom)} phantom, {len(gaps.unreasoned)} unreasoned"
            + (", and its lead-zero config disagrees." if findings.lead_zero_fault else ".")
        )
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
