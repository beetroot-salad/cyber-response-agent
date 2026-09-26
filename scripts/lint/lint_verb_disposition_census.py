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

from defender._paths import adapters_under  # noqa: E402
from defender.learning.leads.declared_systems import (  # noqa: E402
    declared_systems_over,
    read_adapters,
)
from defender.learning.leads.lead_extraction import LeadAuthorError  # noqa: E402
from defender._corpus import QueryTemplate, is_established  # noqa: E402
from defender._tenants import (  # noqa: E402
    TenantDir,
    TenantDirError,
    default_tenants_root,
    tenant_dir,
    template_dir,
)
from defender.runtime import lead_zero as lead_zero_mod  # noqa: E402
from defender.runtime.lead_zero._spec import correlation_grant  # noqa: E402
from defender.runtime.lead_zero_config import LeadZeroConfigError  # noqa: E402
from defender.runtime.run_tenant import catalog_templates, correlation_dispatch  # noqa: E402
from defender.runtime.verb_dispositions import (  # noqa: E402
    DispositionError,
    census_gaps,
    dispositions_path,
    grant_for,
    load_dispositions,
)
from defender.runtime.verb_grant import GrantError  # noqa: E402
from defender.runtime.verbs import RosterRead  # noqa: E402


def _walk(roster: RosterRead, systems: frozenset[str]) -> dict[str, frozenset[str]]:
    return {s: roster.declared_verbs(s) for s in sorted(systems)}


def _unreadable_adapters(
    roster: RosterRead, walked: dict[str, frozenset[str]]
) -> tuple[str, ...]:
    """Systems that HAVE an adapter the walk read no verb out of — the gate's fail-open hole.

    The roster's cold read answers `frozenset()` for an adapter it cannot see into: a source
    that does not parse, or a `VERBS` that is not a top-level dict LITERAL (`VERBS: dict[str,
    Verb] = {...}` is an `AnnAssign` and declares nothing to it, and neither does a table
    assembled in a loop). That polarity is right for `ModuleVerbRegistry`, where an
    unreadable table refuses every grant; it is exactly backwards here, where an empty walk
    yields no `undecided` and the gate prints "clean ... with no residue" over a system
    nobody has decided anything about — #995's own defect wearing this gate's clothes. So an
    adapter that exists and declares nothing is exit 2: the census over it was never taken.

    Adapter PRESENCE (`roster.accepted`) is what separates the two, which is why this is not
    simply "walked to an empty set". An MCP-path system is declared by its committed
    `execution.md` marker and has no adapter module by design (`skills/connect/mcp.md`); it
    is out of this census's reach either way, and failing on it would block a legitimate
    integration.
    """
    return tuple(s for s in sorted(walked) if not walked[s] and s in roster.accepted)


def _tenant_folders(root: Path) -> list[tuple[str, TenantDir | TenantDirError]]:
    """Every tenant folder the gate checks (#1106 M7): each committed tenant under
    `knowledge/tenants/`, then the template — `(name, resolved tenant or the refusal)`, in a
    stable order.

    THROUGH THE RUN'S OWN RESOLVER (`tenant_dir`), so what CI accepts is what a run accepts: a
    tenant with no `agent/` half (git keeps no empty directory, so a missing `.gitkeep` loses
    it in every clone), a missing required file or a linked half is refused here exactly as
    `run.py` would refuse it at start — not passed as clean because its table loads."""
    tenants = default_tenants_root(root)
    names = sorted(d.name for d in tenants.iterdir() if d.is_dir()) if tenants.is_dir() else []
    template = template_dir(root)
    folders: list[tuple[str, TenantDir | TenantDirError]] = []
    for parent, name in [*((tenants, n) for n in names), (template.parent, template.name)]:
        try:
            folders.append((name, tenant_dir(parent, name)))
        except TenantDirError as refusal:
            folders.append((name, refusal))
    return folders


def _lead_zero_fault(settings: Path, rows: tuple, catalog: list[QueryTemplate]) -> str | None:
    """Each folder's lead-zero config, checked in CI (#1106 M7): it names an ESTABLISHED
    catalog template — whether or not the table grants the lead, since a withheld lead's id is
    never consulted at run start and would otherwise surface only once an operator grants it —
    and, when the table does grant the lead, that template's pair is the one granted (the
    run-start agreement check itself, `run_tenant.correlation_dispatch`). `None` when both
    hold. `catalog` is the tree's, walked once for every folder."""
    try:
        template_id = correlation_dispatch(settings, catalog, correlation_grant(rows)).template_id
    except (LeadZeroConfigError, lead_zero_mod.CorrelationDispatchError, GrantError) as e:
        return str(e)
    if not any(t.id == template_id and is_established(t) for t in catalog):
        return (f"correlation_template {template_id!r} names no established template in the "
                "catalog (the table withholds the lead, so no run consults it yet)")
    return None


def main(argv: list[str]) -> int:  # noqa: C901, PLR0912 — one gate over every folder; each exit arm is a distinct verdict
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(REPO_ROOT), help="repo root to check")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    defender_dir = root / "defender"

    # Exit 2, not 1, when the gate could not RUN. An unreadable source or an unloadable table
    # means the census was never taken, and a gate that prints "0 findings" because it scanned
    # nothing is categorically not clean (#618/#621/#652). ONE roster read for this gate — the
    # resolver's own (`read_adapters`, which raises this lane's `LeadAuthorError` for a tree
    # it cannot read) — and both the system set and the verb walk below are that one value:
    # two reads would let a tree that changed between them score one read's systems against
    # the other's verbs.
    try:
        roster = read_adapters(adapters_under(defender_dir))
        systems = declared_systems_over(roster, root)
    except LeadAuthorError as e:
        print(f"lint_verb_disposition_census: cannot resolve systems: {e}", file=sys.stderr)
        return 2

    walked = _walk(roster, systems)
    blind = _unreadable_adapters(roster, walked)
    if blind:
        print(
            f"lint_verb_disposition_census: {list(blind)} have an adapter the cold verb "
            "reader saw no verb in, so no census over them was taken and their absence from "
            "the table means nothing. The adapter does not parse, or declares `VERBS` as "
            "something other than a top-level dict literal — an annotated assignment "
            "(`VERBS: dict[str, Verb] = {...}`) or a table built in a loop declares nothing "
            "to the reader. Fix the adapter.",
            file=sys.stderr,
        )
        for system in blind:
            if system in roster.unparsed:
                print(
                    f"lint_verb_disposition_census: {system}: {roster.unparsed[system]}",
                    file=sys.stderr,
                )
        return 2

    # EVERY TENANT AND THE TEMPLATE (#1106 M7). Grants describe the SHARED adapters, so each
    # folder's table must be total over the one walked census; a folder whose table cannot even
    # load is exit 2 for the same reason an unreadable adapter is.
    worst = 0
    catalog = catalog_templates(defender_dir)
    for name, resolved in _tenant_folders(root):
        if isinstance(resolved, TenantDirError):
            print(f"lint_verb_disposition_census: {name}: a run would refuse this tenant at "
                  f"start: {resolved}", file=sys.stderr)
            worst = 2
            continue
        settings = resolved.settings
        try:
            rows = load_dispositions(dispositions_path(settings))
        except DispositionError as e:
            print(f"lint_verb_disposition_census: {name}: {e}", file=sys.stderr)
            worst = 2
            continue
        table = dispositions_path(settings).relative_to(root)
        gaps = census_gaps(walked, rows)
        lead_zero_fault = _lead_zero_fault(settings, rows, catalog)
        if not gaps and lead_zero_fault is None:
            print(
                f"lint_verb_disposition_census: {name}: clean — {len(rows)} dispositions "
                f"cover {len(systems)} system(s) with no residue "
                f"({len(grant_for('gather', rows).entries)} granted to gather)."
            )
            continue
        worst = max(worst, 1)
        for system, verb in gaps.undecided:
            print(
                f"{name}: {system}.{verb}: declared by an adapter, decided by nobody. Add a "
                f"row to {table} granting it to a role, or `roles: []` with a reason if it is "
                "deliberately reachable by no one."
            )
        for system, verb in gaps.phantom:
            print(
                f"{name}: {system}.{verb}: the table decides a verb no adapter declares. "
                f"Remove the row from {table}, or restore the verb."
            )
        for system, verb in gaps.unreasoned:
            print(f"{name}: {system}.{verb}: granted to nobody with no reason given.")
        if lead_zero_fault is not None:
            print(f"{name}: lead-zero: {lead_zero_fault}")
        print(
            f"lint_verb_disposition_census: {name}: {len(gaps.undecided)} undecided, "
            f"{len(gaps.phantom)} phantom, {len(gaps.unreasoned)} unreasoned"
            + (", and its lead-zero config disagrees." if lead_zero_fault is not None else ".")
        )
    return worst

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
