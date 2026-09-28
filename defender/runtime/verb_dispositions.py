"""The verb-disposition table: the one authored answer to "who may call what".

Which systems exist, which verbs each declares and what params each takes are derived by
walking the adapters. Which of those any role may call is authored here by a human. The second
must never be derived from the first: an adapter file appearing on disk would then grant itself
read access to the estate. `grant_for` reads only the table, never the filesystem.

What is derived instead is the obligation to decide: `census_gaps` reports residue in both
directions, so a new system can be ungranted only on the record, with a reason.

The table lives in each tenant's `settings/` folder as data, so the shipped runtime carries no
vendor names and a product with no table grants nothing. That is safe only because
`load_dispositions` refuses an absent or empty table.

A row's `roles:` names grant holders: gather, or `lead-zero-correlation`, the turn-zero
correlation lead. The lead runs under gather's key (`agent_role.CORRELATION_GRANT_HOLDER`) but
holds its own narrower projection; `_refuse_incoherent_narrowing` keeps it a narrowing. Which
query verb the lead uses is the tenant's `lead-zero.yaml` template's to say, and
`lead_zero._agreement` refuses at run start a table granting the lead any other.

There is no `verb_class` field: every shipped verb is read-class and the projection hardcodes
`r`, so a write grant costs a schema change and its own review rather than a one-word data edit.
"""
from __future__ import annotations

import warnings
from collections.abc import Mapping
from defender._model import model
from pathlib import Path

from defender import _yaml
from defender.runtime.agent_role import CORRELATION_GRANT_HOLDER, AgentRole
from defender.runtime.verb_grant import VerbGrant
from defender.runtime.verbs import is_system_name

#: The table's filename inside a tenant's `settings/` folder. The folder is resolved per run
#: from its tenant and handed down, since one process may serve several tenants.
DISPOSITIONS_FILENAME = "verb-grants.yaml"

#: The grant holders a row's `roles:` may name. Sourced from `agent_role` so a rename cannot
#: leave a table granting to a name nothing answers to. The family judge role is absent because
#: it holds no verb grant; a row may only name a holder some caller claims.
KNOWN_ROLES: frozenset[str] = frozenset({
    AgentRole.GATHER.value, CORRELATION_GRANT_HOLDER,
})

#: Every shipped disposition is read-class; not a table field, so a write grant needs a schema change.
READ_CLASS = "r"

#: The verb every adapter declares and `/connect` tests a new system with; `load_dispositions`
#: treats it specially (see `_warn_unhealth_checkable`).
HEALTH_CHECK = "health-check"


class DispositionError(Exception):
    """Raised for any table this module will not stand behind.

    One exception for every failure, since each has the same handling at startup: stop. A
    half-loaded table would be an accidental deny-all, so there is no partial success.
    """


class DispositionWarning(UserWarning):
    """A table that loads, and that a human should look at anyway.

    Not a raise: the grants are coherent and the runtime is sound; only the operator's intent
    is likely wrong, which does not justify stopping a deployment.
    """


@model(frozen=True)
class Disposition:
    """One `(system, verb)` and the roles allowed to call it.

    `roles` empty means granted to nobody, a decision that requires `reason`. That differs
    from the pair being absent from the table, which is residue `census_gaps` reports.
    """

    system: str
    verb: str
    roles: frozenset[str]
    reason: str | None = None

    @property
    def pair(self) -> tuple[str, str]:
        return (self.system, self.verb)


@model(frozen=True)
class CensusGaps:
    """Residue between the walked census and the table, in both directions.

    Separate fields because they have different remedies: `undecided` needs a human decision;
    `phantom` is a row that outlived its verb; `unreasoned` is a withholding without a reason.

    A withheld health-check is not checked here: the census runs only in CI, while operators
    edit their own per-deployment tables, so `load_dispositions` warns about it on every load.
    """

    undecided: tuple[tuple[str, str], ...] = ()
    phantom: tuple[tuple[str, str], ...] = ()
    unreasoned: tuple[tuple[str, str], ...] = ()

    def __bool__(self) -> bool:
        return bool(self.undecided or self.phantom or self.unreasoned)


def dispositions_path(settings_dir: Path) -> Path:
    """The table's path inside a tenant's `settings/` folder."""
    return Path(settings_dir) / DISPOSITIONS_FILENAME


@model(frozen=True)
class RunGrants:
    """The grants one run holds, projected from its tenant's table.

    A per-run value, not a module constant, so one process can serve several tenants. `path`
    is the resolved table, named in operator-facing refusals only; the model is told
    `run_tenant.table_pointer` instead, since the settings host path is not the model's to read.

    `correlation_system` is derived from `correlation` (`None` when the table withholds the
    lead), so the two cannot drift.
    """

    path: Path
    gather: VerbGrant
    correlation: VerbGrant
    correlation_system: str | None


def run_grants(settings_dir: Path) -> RunGrants:
    """Load `settings_dir`'s table and project the run's grants from it. @owns RunGrants

    Uncached, so each run in a process reads its own (possibly edited) table. A missing or
    malformed table raises `DispositionError`; an absent table is not a deny-all.
    """
    from defender.runtime.lead_zero._spec import correlation_grant, correlation_system

    path = dispositions_path(settings_dir).resolve()
    rows = load_dispositions(path)
    correlation = correlation_grant(rows)
    return RunGrants(
        path=path,
        gather=grant_for(AgentRole.GATHER.value, rows),
        correlation=correlation,
        correlation_system=correlation_system(correlation),
    )


def require_gather_query(grants: RunGrants) -> None:
    """Refuse a run's grants under which gather can query nothing.

    A `health-check` grant alone is not a query: such a table loads, then denies every `query`
    mid-run after model calls are spent. Shared by the run start and `defender-policy`."""
    if not any(verb != HEALTH_CHECK for _system, verb, _ in grants.gather.entries):
        raise DispositionError(
            f"{grants.path} grants gather no query verb — a run could query nothing (a "
            f"`{HEALTH_CHECK}` grant alone reaches no data). Grant gather at least one (system, "
            "verb) there before running this tenant (a tenant copied from the template grants "
            "nothing)."
        )


def _systems_block(path: Path) -> Mapping[object, object]:
    """Read the file and return its `dispositions:` mapping, or raise."""
    data = _yaml.load_reviewed_mapping(
        path, what="verb-disposition table", known=("dispositions",), error=DispositionError,
    )
    systems = data.get("dispositions")
    if systems is not None and not isinstance(systems, Mapping):
        # Distinct from the empty case: a list is a shape mistake, not missing rows.
        raise DispositionError(
            f"verb-disposition table at {path} has a `dispositions:` that is "
            f"{type(systems).__name__}, not a mapping of system to verb rows"
        )
    if not systems:
        raise DispositionError(
            f"verb-disposition table at {path} declares no dispositions. An empty table is "
            "not a deny-all — it is indistinguishable from a table that failed to load, "
            "which is the silent-mute failure this file exists to prevent. Grant nothing by "
            "writing rows with `roles: []` and a reason."
        )
    return systems


def _reject_unread_keys(
    where: str, mapping: Mapping[object, object], known: tuple[str, ...]
) -> None:
    """Refuse a row key nothing reads (e.g. `class: rw`, or a misspelled `resaon:` that would
    leave a withholding unexplained while looking explained)."""
    _yaml.reject_unread_keys(where, mapping, known, error=DispositionError)


def load_dispositions(path: Path) -> tuple[Disposition, ...]:
    """Parse and validate the table at `path`. Raises `DispositionError` on anything doubtful.

    Validation is total, not best-effort: a partly loaded permission table would grant a
    coherent-looking subset. Every refusal names the offending system or pair.
    """
    path = Path(path)
    systems = _systems_block(path)
    rows: list[Disposition] = []
    for system, verbs in sorted(systems.items(), key=lambda kv: str(kv[0])):
        if not isinstance(system, str) or not is_system_name(system):
            raise DispositionError(f"{path}: {system!r} is not a well-formed system name")
        # Distinct from the empty case: a list is a shape mistake, not missing rows.
        if verbs is not None and not isinstance(verbs, Mapping):
            raise DispositionError(
                f"{path}: system {system!r} carries {type(verbs).__name__}, not a mapping of "
                "verb name to row"
            )
        if not verbs:
            raise DispositionError(f"{path}: system {system!r} carries no verb rows")
        for verb_name, body in sorted(verbs.items(), key=lambda kv: str(kv[0])):
            rows.append(_disposition_row(path, system, verb_name, body))
    out = tuple(rows)
    _refuse_incoherent_narrowing(path, out)
    _warn_unhealth_checkable(path, out)
    return out


def _refuse_incoherent_narrowing(path: Path, rows: tuple[Disposition, ...]) -> None:
    """Refuse a table under which the correlation lead is not a narrowing of gather.

    * The lead never holds a pair gather does not: it runs under gather's policy, tools and
      trace. Withholding a pair from the lead alone is fine and only degrades the run.
    * The lead's rows reach at most one system, since it is dispatched against exactly one.
    * The lead holds at most one query verb. It is dispatched by the harness with no model
      choosing to spend it, and index confinement depends on which verb it holds (search verbs
      are confined, native-query verbs are not). Without this rule, adding the lead to a wider
      verb gather already holds would pass the other two rules and hand it an unconfined read.
      Which verb is checked at run start by `lead_zero._agreement`, where the template is known.

    `health-check` is excluded from the last two rules: it is never a dispatch target, so
    counting it would refuse an unambiguous table.
    """
    gather = AgentRole.GATHER.value
    for d in rows:
        if CORRELATION_GRANT_HOLDER in d.roles and gather not in d.roles:
            raise DispositionError(
                f"{path}: {d.system}.{d.verb} is granted to {CORRELATION_GRANT_HOLDER!r} and "
                f"not to {gather!r}. The correlation lead runs under {gather}'s policy and "
                f"holds a narrowing of its grant, so it may not hold a pair {gather} does "
                "not — grant the pair to both, or withhold it from both."
            )
    queries = [
        d for d in rows
        if CORRELATION_GRANT_HOLDER in d.roles and d.verb != HEALTH_CHECK
    ]
    systems = sorted({d.system for d in queries})
    if len(systems) > 1:
        raise DispositionError(
            f"{path}: {CORRELATION_GRANT_HOLDER!r} reaches {len(systems)} systems "
            f"({systems}). The correlation lead is dispatched against ONE system, and which "
            "one is a deliberate authoring choice — grant the lead rows on that system alone."
        )
    if len(queries) > 1:
        named = sorted(f"{d.system}.{d.verb}" for d in queries)
        raise DispositionError(
            f"{path}: {CORRELATION_GRANT_HOLDER!r} holds {len(queries)} query verbs "
            f"({named}). The correlation lead is dispatched by the harness, binds ONE "
            "template and makes one kind of call, and its index confinement is a property of "
            "which verb that is — a second one widens a lead no model chose to spend past "
            "the pair its contract was written for. Grant it one query verb plus "
            f"{HEALTH_CHECK!r}, or withhold it from every row and let the lead be skipped."
        )


def _warn_unhealth_checkable(path: Path, rows: tuple[Disposition, ...]) -> None:
    """Warn where gather can query a system and cannot health-check it.

    Checked on load rather than in CI because the table is per-deployment data an operator
    edits. A warning, not a raise: health probes degrade but nothing becomes unsafe.

    Reads the rows only, never the tree, so it cannot tell a withheld health-check from an
    adapter that declares none; the message covers both.
    """
    gather = AgentRole.GATHER.value
    reached = {d.system for d in rows if gather in d.roles}
    checkable = {d.system for d in rows if gather in d.roles and d.verb == HEALTH_CHECK}
    for system in sorted(reached - checkable):
        warnings.warn(
            f"{path}: system {system!r} grants gather no {HEALTH_CHECK!r}. Gather can query "
            f"it and cannot check whether it is up, so `/connect`'s test step and the "
            f"runtime's nothing-to-try paths have nothing to probe it with. If its adapter "
            f"declares {HEALTH_CHECK!r}, grant {system}.{HEALTH_CHECK} to gather; if it "
            f"declares none, withhold {system!r} from gather entirely — a row for a verb no "
            f"adapter declares is residue the census reports as a phantom.",
            DispositionWarning,
            stacklevel=2,
        )


def _disposition_row(
    path: Path, system: str, verb_name: object, body: object
) -> Disposition:
    where = f"{path}: {system}.{verb_name}"
    # `SYSTEM_PATTERN` spells verb names too. Checked here because an admitted row reaches the
    # refusal text and the generated roster even if nothing cross-checks it against an adapter.
    if not isinstance(verb_name, str) or not is_system_name(verb_name):
        raise DispositionError(f"{where}: {verb_name!r} is not a well-formed verb name")
    if not isinstance(body, Mapping):
        raise DispositionError(f"{where} must be a mapping with a `roles:` key")

    # `roles` and `reason` are the whole row schema; a new field is a change to this module.
    _reject_unread_keys(where, body, ("roles", "reason"))

    # An absent `roles` is an unfinished row, not a withholding; defaulting to `[]` would make
    # a half-written table withhold silently.
    if "roles" not in body:
        raise DispositionError(f"{where} has no `roles:` key")
    raw_roles = body["roles"]
    if not isinstance(raw_roles, list):
        raise DispositionError(f"{where}: `roles` must be a list")
    roles: list[str] = []
    for role in raw_roles:
        if not isinstance(role, str) or role not in KNOWN_ROLES:
            raise DispositionError(f"{where}: {role!r} is not a role ({sorted(KNOWN_ROLES)})")
        roles.append(role)
    if len(set(roles)) != len(roles):
        raise DispositionError(f"{where}: `roles` repeats a role")

    reason = body.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise DispositionError(f"{where}: `reason` must be text")
    if not roles and not (reason or "").strip():
        # `.strip()`: a whitespace-only reason records nothing for a human to read.
        raise DispositionError(
            f"{where} is granted to nobody and gives no reason. A residue entry that costs "
            "nothing to add is a free way to silence the census gate — say why."
        )
    return Disposition(
        system=system, verb=verb_name, roles=frozenset(roles), reason=reason,
    )


def grant_for(role: str, dispositions: tuple[Disposition, ...]) -> VerbGrant:
    """Project the table onto one role's `VerbGrant`.

    Reads the parsed rows only (no filesystem, no registry), so a dropped-in adapter cannot
    grant itself. A known role no row names gets an empty grant. An unknown role raises: a
    call-site typo would otherwise be an accidental deny-all indistinguishable from a
    deliberate withholding.
    """
    if role not in KNOWN_ROLES:
        raise DispositionError(
            f"{role!r} is not a role ({sorted(KNOWN_ROLES)}). A projection for an unknown role "
            "would be an empty grant, which every reader downstream cannot tell apart from a "
            "deliberate withholding."
        )
    entries = tuple(
        (d.system, d.verb, READ_CLASS)
        for d in dispositions
        if role in d.roles
    )
    return VerbGrant(role=role, entries=entries)


def census_gaps(
    walked: Mapping[str, frozenset[str]], dispositions: tuple[Disposition, ...]
) -> CensusGaps:
    """Residue between what the tree declares and what the table decides.

    Pure: `walked` is supplied by the CI gate, since resolving it runs git and this module is
    imported while the runtime builds agent definitions. `undecided` is a declared verb the table
    ignores (silently ungranted); `phantom` is a row for a verb no adapter declares, which would
    otherwise surface later as a startup failure.
    """
    decided = {d.pair for d in dispositions}
    declared = {(system, verb) for system, verbs in walked.items() for verb in verbs}
    return CensusGaps(
        undecided=tuple(sorted(declared - decided)),
        phantom=tuple(sorted(decided - declared)),
        unreasoned=tuple(sorted(
            d.pair for d in dispositions if not d.roles and not (d.reason or "").strip()
        )),
    )


__all__ = [
    "DISPOSITIONS_FILENAME",
    "HEALTH_CHECK",
    "KNOWN_ROLES",
    "READ_CLASS",
    "CensusGaps",
    "Disposition",
    "DispositionError",
    "DispositionWarning",
    "census_gaps",
    "dispositions_path",
    "grant_for",
    "load_dispositions",
    "require_gather_query",
    "run_grants",
    "RunGrants",
]
