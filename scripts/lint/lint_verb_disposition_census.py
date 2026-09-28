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

# The resolver and loader are imported, never reimplemented: a gate re-deriving "which
# systems exist" with its own glob would be one more hand-maintained answer to the question
# this gate exists to unify.
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
    """Systems that have an adapter the walk read no verb out of — the gate's fail-open hole.

    The roster's cold read answers `frozenset()` for an adapter it cannot see into: a source
    that does not parse, or a `VERBS` that is not a top-level dict literal (an annotated
    `VERBS: dict[str, Verb] = {...}` or a table built in a loop declares nothing). That is
    right for `ModuleVerbRegistry`, where an unreadable table refuses every grant, but here an
    empty walk yields no `undecided` and would print "clean" over an undecided system. So an
    adapter that exists and declares nothing is exit 2.

    Adapter presence (`roster.accepted`) separates this from an MCP-path system, which is
    declared by its committed `execution.md` marker and has no adapter module by design; it is
    out of this census's reach, and failing on it would block a legitimate integration.
    """
    return tuple(s for s in sorted(walked) if not walked[s] and s in roster.accepted)


def _tenant_folders(root: Path) -> list[tuple[str, TenantDir | TenantDirError]]:
    """Every tenant folder the gate checks — each committed tenant under
    `knowledge/tenants/`, then the template — as `(name, resolved tenant or the refusal)`, in a
    stable order.

    Resolved through the run's own resolver (`tenant_dir`), so what CI accepts is what a run
    accepts: a tenant with no `agent/` half (git keeps no empty directory, so a missing
    `.gitkeep` loses it in every clone), a missing required file or a linked half is refused
    here as `run.py` would refuse it at start."""
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
    """Each folder's lead-zero config, checked in CI: it names an established catalog
    template — even when the table withholds the lead, since a withheld lead's id is never
    consulted at run start and would surface only once an operator grants it — and, when the
    lead is granted, that template's pair is the one granted (the run-start agreement check,
    `run_tenant.correlation_dispatch`). `None` when both hold. `catalog` is walked once for
    every folder."""
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

    # Exit 2, not 1, when the census was never taken (unreadable source or table). One
    # roster read serves both the system set and the verb walk, so a tree changing between
    # two reads cannot score one read's systems against the other's verbs.
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

    # Every tenant and the template. Grants describe the shared adapters, so each folder's
    # table must be total over the one walked census; an unloadable table is exit 2.
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
