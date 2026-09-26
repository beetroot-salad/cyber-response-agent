"""The verb-disposition table — the one authored answer to "who may call what".

WHY THIS EXISTS (#995). The gather grant used to be a tuple of `(system, verb)` pairs in
`driver/_build.py`, and the judge's a second tuple in another package. A pair not listed was
not granted, so a newly connected system was reachable only if a human remembered to edit a
file that `/connect`'s own lane rules forbid it to touch — and the failure was not even a
denial. A real, declared verb on an ungranted system came back `UNDECLARED`, wording
identical to a typo's, so the symptom pointed at a spelling mistake in an adapter that was
correct.

WHAT IS DERIVED AND WHAT IS AUTHORED — the whole design is this line.

  DERIVED, by walking:  which systems exist, which verbs each declares, what params each takes.
  AUTHORED, by a human: which of those any role may call.

Deriving the second from the first is the one repair that must never be made: it would mean
an adapter file appearing on disk grants itself read access to the estate. `verb_grant.py`
says the same thing about the type this module produces — "authored data, not a filter
derived from the registry" — and nothing here weakens it. `grant_for` reads the table and
only the table; it never touches the filesystem, and `test_the_grant_is_not_a_function_of_
what_is_on_disk` is the probe that keeps it honest.

What #995 derives instead is the OBLIGATION TO DECIDE. `census_gaps` compares the walked
census against the table and reports residue in both directions, so a new system cannot be
silently ungranted — only ungranted on the record, with a reason a reviewer can read. That is
strictly stronger than the old property: before, a new system was ungranted by accident.

WHY A CONFIG FILE RATHER THAN A PYTHON LITERAL. The table is this deployment's answer about
this deployment's systems, so it lives in each tenant's `settings/` folder as data (#1106). Two consequences that
are features: the shipped runtime stops carrying vendor names, and a product with no table
grants nothing. The second is only safe because `load_dispositions` REFUSES an absent or
empty table rather than returning one — every refusal below is a raise.

WHO A ROW MAY NAME. `roles:` carries GRANT HOLDERS, and a holder is a role that projects a
grant — gather, and gather alone since #922 retired the judge — or ONE named narrowing of a
role: `lead-zero-correlation`, the turn-zero correlation lead (#999). That lead is not a role
(it runs under gather's key; see `agent_role.CORRELATION_GRANT_HOLDER`), but it holds its own,
narrower projection, and before #999 that projection was a `VerbGrant` literal in Python that
no row here could widen or withdraw — the two-statements-one-honoured defect this file exists
to end, surviving in the one grant the census could not see. Naming the lead here is what
makes the table total over GRANTS and not only over adapters. `_refuse_incoherent_narrowing`
holds the three rules that keep "narrowing" true: the lead never holds a pair gather does not,
reaches one system, and holds one query verb. Which query verb is the TEMPLATE's to say
(the tenant's `lead-zero.yaml` names it; its front matter declares the pair), and
the run refuses at start if this table grants the lead any other (#1003,
`lead_zero._agreement`) — the table grants or withholds the lead; it does not relocate it.

WHY NO `verb_class` FIELD. Every shipped verb is read-class and the projection hardcodes `r`.
That is deliberate under-expression: a write grant should cost a schema change and its own
review, not a one-word edit to a data file. Adding `rw` here later is a change to this
module, which is the friction that decision deserves.
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

#: The table's filename inside a tenant's `settings/` folder (#1106), and the one place it is
#: spelled. The folder is the RUN's — resolved from its tenant by `defender._tenants` and handed
#: down — never a path this module works out: a table read from a fixed place is one table per
#: process, and the platform holds one per tenant.
DISPOSITIONS_FILENAME = "verb-grants.yaml"

#: The names a row's `roles:` may carry — the grant holders (module docstring, "WHO A ROW MAY
#: NAME"). Sourced from `agent_role` rather than respelled, so a name that is renamed cannot
#: leave a table silently granting to a name nothing answers to. `judge` left this set in #922
#: with the role itself; every row that named it now carries `roles: []` and a reason, so the
#: verbs are still described and still granted to nobody. #1008 re-added the ROLE for the
#: family judge, and deliberately not this name: the family judge holds no verb grant, and a
#: row may only name a holder some caller actually claims.
KNOWN_ROLES: frozenset[str] = frozenset({
    AgentRole.GATHER.value, CORRELATION_GRANT_HOLDER,
})

#: Every shipped disposition is read-class. See the module docstring for why this is not a
#: field in the file.
READ_CLASS = "r"

#: The verb every adapter declares and `/connect` step 5 tests a new system with. Spelled here
#: because `load_dispositions` has a rule about it that no other verb has — see
#: `_warn_unhealth_checkable`.
HEALTH_CHECK = "health-check"


class DispositionError(Exception):
    """Raised for any table this module will not stand behind.

    One exception for every failure — absent file, unparseable text, unknown role, reasonless
    withholding — because every one of them has the same correct handling at startup: stop.
    A table that half-loaded is the deny-all-by-accident state #995 exists to make
    unreachable, so there is no partial-success path to distinguish.
    """


class DispositionWarning(UserWarning):
    """A table that loads, and that a human should look at anyway.

    Separate from `DispositionError` because the two have different correct handlings, and the
    distinction is the whole reason this is not a raise: every refusal in this module is a
    condition under which no grant can be trusted, so startup must stop. A withheld
    health-check is not that. The permissions it describes are coherent and the runtime built
    from them is sound — it is the OPERATOR's intent that is likely wrong, and stopping a
    deployment over a likely-wrong intent trades a broken health check for a dead product.
    """


@model(frozen=True)
class Disposition:
    """One `(system, verb)` and the roles allowed to call it.

    `roles` empty means granted to nobody, which is a DECISION and therefore requires
    `reason`. It is not the same as the pair being absent from the table — absence is residue
    and `census_gaps` reports it. Keeping those two apart is the point of the whole file.
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

    Three fields rather than one list of findings: they have different remedies. `undecided`
    means a human must decide something; `phantom` means a row outlived its verb; `unreasoned`
    means a decision was made without saying why.

    A withheld health-check is deliberately NOT here. This whole census is a repo-time
    comparison — it needs the walked tree, so only CI ever runs it — and the table is
    per-deployment data. An operator editing their own copy never reaches this code, so a rule
    living here would be enforced exactly where it is least needed. `load_dispositions` warns
    about it instead, on every load, everywhere.
    """

    undecided: tuple[tuple[str, str], ...] = ()
    phantom: tuple[tuple[str, str], ...] = ()
    unreasoned: tuple[tuple[str, str], ...] = ()

    def __bool__(self) -> bool:
        return bool(self.undecided or self.phantom or self.unreasoned)


def dispositions_path(settings_dir: Path) -> Path:
    """The table's path inside a tenant's `settings/` folder.

    Takes the folder rather than reading a module-level constant: the run resolves its own
    tenant's folder, and the lint gate walks every committed tenant's — neither is a place this
    module could know.
    """
    return Path(settings_dir) / DISPOSITIONS_FILENAME


@model(frozen=True)
class RunGrants:
    """The grants ONE run holds, projected from its tenant's table (#1106 O3, M4).

    A value that travels with the run, never a module constant: before #1106 the table was read
    once per process at import and these three were module-level, so a process could only ever
    hold one tenant's permissions. `path` is the resolved table they came from — the file an
    OPERATOR-facing refusal names. What the model is told is `run_tenant.table_pointer`: the
    settings half is host-only, and its host path is not the model's to read.

    `correlation_system` is derived from `correlation` (the one system item 3 is dispatched
    against, `None` when the table withholds the lead), so the two cannot drift.
    """

    path: Path
    gather: VerbGrant
    correlation: VerbGrant
    correlation_system: str | None


def run_grants(settings_dir: Path) -> RunGrants:
    """Load `settings_dir`'s table and project the run's grants from it. @owns RunGrants

    Read on every call — no cache — so two runs in one process over two tenants (or over one
    folder edited between them) each get their own table. A missing or malformed table raises
    `DispositionError` from `load_dispositions`, as it always has: an absent table is not a
    deny-all.
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
    """Refuse a run's grants under which gather can QUERY nothing — the one "grants nothing"
    refusal.

    A `health-check` grant is not a query: a table granting gather only health checks loads,
    binds, and then answers every `query` DENIED mid-run — after the box is up and MAIN has
    spent model calls. The one predicate every caller asks (the run start, `defender-policy`),
    so none of them can count a health check as a grant."""
    if not any(verb != HEALTH_CHECK for _system, verb, _ in grants.gather.entries):
        raise DispositionError(
            f"{grants.path} grants gather no query verb — a run could query nothing (a "
            f"`{HEALTH_CHECK}` grant alone reaches no data). Grant gather at least one (system, "
            "verb) there before running this tenant (a tenant copied from the template grants "
            "nothing)."
        )


def _systems_block(path: Path) -> Mapping[object, object]:
    """Read the file and return its `dispositions:` mapping, or raise.

    Split out from `load_dispositions` so that function stays one job — turning rows into
    `Disposition`s — rather than two. Everything about the FILE being trustworthy at all is
    `_yaml.load_reviewed_mapping`'s (shared with `lead-zero.yaml`'s loader, #1003); everything
    here is about the one key's shape, and everything there about a row being well formed.
    """
    data = _yaml.load_reviewed_mapping(
        path, what="verb-disposition table", known=("dispositions",), error=DispositionError,
    )
    systems = data.get("dispositions")
    if systems is not None and not isinstance(systems, Mapping):
        # Said apart from the empty case below: a `dispositions:` that is a LIST is a shape
        # mistake, and "declares no dispositions" sends the author looking for missing rows.
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
    """A row carrying a key nothing here reads is refused as `DispositionError` — the same
    two-statements-one-honoured defect `_yaml.reject_unread_keys` names at the top level,
    one level down (`class: rw` on a row; a misspelled `resaon:` leaving a withholding
    unexplained while looking explained)."""
    _yaml.reject_unread_keys(where, mapping, known, error=DispositionError)


def load_dispositions(path: Path) -> tuple[Disposition, ...]:
    """Parse and VALIDATE the table at `path`. Raises `DispositionError` on anything doubtful.

    Every refusal names the offending system or pair. That is not politeness: the failure is
    read at startup by someone who has just connected a system, and "invalid table" sends them
    back to bisect a file by hand.

    The validation is deliberately total rather than best-effort. A permission table that
    loaded 90% of its rows would grant a coherent-looking subset, and the missing 10% would
    present exactly as this issue's original symptom.
    """
    path = Path(path)
    systems = _systems_block(path)
    rows: list[Disposition] = []
    for system, verbs in sorted(systems.items(), key=lambda kv: str(kv[0])):
        if not isinstance(system, str) or not is_system_name(system):
            raise DispositionError(f"{path}: {system!r} is not a well-formed system name")
        # The shape mistake said APART from the empty one, for the reason `_systems_block`
        # separates them at the level above: "carries no verb rows" sends the author looking
        # for rows to add, which is the wrong job when the rows are there and the container
        # around them is a list.
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
    """Refuse a table under which the correlation lead is not a narrowing of gather (#999).

    Three rules, and all three RAISE rather than warn, because each is a table no coherent
    grant can be built from — the standard every other refusal in this module meets:

    * The lead never holds a pair gather does not. It is bound from `GATHER_DEF` — gather's
      compiled policy, gather's tools, gather's trace — so a pair only the lead holds is a
      grant reaching a lead whose own role cannot. Withholding a pair from BOTH holders, or
      from the lead alone, is fine: those are withholdings, and a withholding degrades the run
      rather than stopping it (`lead_zero._spec`).
    * The lead's rows reach at most one system. It is dispatched against exactly one — the
      system selects the template index's on-target tier and the prompt-cache lane — so a
      table naming two is an authoring ambiguity. Refused here, where the rows are and
      naming both systems, rather than as a `GrantError` out of `lead_zero` at import.
    * The lead holds at most ONE query verb. This is the rule that keeps the safety case a
      table edit cannot quietly widen. The lead is dispatched by the HARNESS, with no model
      choosing to spend it, and whether its reads are index-confined is a property of WHICH
      verb it holds — an adapter's search verbs go through its confinement helper and its
      native-query verb does not. The subset-of-gather rule cannot see that, because the
      wider verb IS granted to gather: adding the lead to that row passes the first two rules
      and hands a harness-dispatched lead an unconfined read, for a one-word edit. Before
      #999 that widening cost a Python change; this is what keeps the cost. The lead's own
      contract binds ONE template and makes one kind of call
      (the template `lead-zero.yaml` names), so one query verb is also all it can spend —
      and WHICH one is not this loader's to check: the template the config names declares
      its own pair, and `lead_zero._agreement` refuses at run start a table whose one query
      pair is not that one (#1003). This module has no catalog to resolve the template
      against and is read at import by `lead_zero._spec`, so that fourth rule lives one
      level up, where the run's tree is in hand.

    `health-check` is excluded from the last two rules on purpose. It is never a dispatch
    target and never selects one — `lead_zero._spec.correlation_system` filters it out before
    deriving the system — so counting it would refuse a table whose dispatch target is
    perfectly unambiguous, which is not what a raise in this module means.
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

    A WARNING, and loaded rather than linted, for two reasons that pull the same way.

    LOADED, not linted, because this file is per-deployment data. A CI gate over the repo's own
    copy says nothing about the table an operator edits, and that operator is the only person
    who can author this mistake — so a repo-time check would run exactly where it is not
    needed and be silent where it is. Every load reaches here: the runtime's, the lint gate's,
    a deployment's.

    A WARNING, not a raise, because the state is recoverable and refusing it is not. `/connect`
    step 5's health check and the runtime's nothing-to-try paths degrade; nothing becomes
    unsafe, and no grant becomes untrustworthy. Every raise in this module is a table no grant
    can be built from, which is why they stop startup. Stopping a deployment over a
    health-check an operator may have withheld on purpose would trade a degraded probe for a
    dead product.

    Reads the ROWS ONLY, never the tree. The loader's standing property is that it touches no
    filesystem beyond `path` (a walk here would put "what is on disk" back into the answer),
    so this cannot tell "the author withheld health-check" from "the adapter declares none".
    Both are worth the same sentence — gather reaches this system and cannot health-check it —
    so the message states that and does not guess which.
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
    # `is_system_name`, on the VERB too: `verbs.SYSTEM_PATTERN` is documented as spelling both
    # ("the tree declares no verb outside it and has no separate verb pattern"), and shape is
    # checked here rather than left to `ModuleVerbRegistry` because the registry is not the
    # only consumer of a projected grant — a row this loader admits reaches the refusal text
    # and the generated roster whether or not anything cross-checks it against an adapter.
    if not isinstance(verb_name, str) or not is_system_name(verb_name):
        raise DispositionError(f"{where}: {verb_name!r} is not a well-formed verb name")
    if not isinstance(body, Mapping):
        raise DispositionError(f"{where} must be a mapping with a `roles:` key")

    # `roles` and `reason` are the whole row schema; adding a third is a change to this module
    # (see the module docstring on why that friction is the point).
    _reject_unread_keys(where, body, ("roles", "reason"))

    # An ABSENT `roles` is an unfinished row, not a withholding. Defaulting it to `[]` would
    # make a half-written table withhold silently — the same class as everything else here.
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
        # `.strip()`, not truthiness: `reason: ""` and `reason: "   "` both satisfy a presence
        # check while recording nothing, and this field's only job is to be read by a human.
        raise DispositionError(
            f"{where} is granted to nobody and gives no reason. A residue entry that costs "
            "nothing to add is a free way to silence the census gate — say why."
        )
    return Disposition(
        system=system, verb=verb_name, roles=frozenset(roles), reason=reason,
    )


def grant_for(role: str, dispositions: tuple[Disposition, ...]) -> VerbGrant:
    """Project the table onto one role's `VerbGrant`.

    Reads the table and NOTHING else — no filesystem, no registry. That is the property
    keeping a dropped-in adapter from granting itself, and it is why this function takes the
    parsed rows rather than a path it could be tempted to walk beside.

    A KNOWN role no row names yields an empty grant, because this is a filter and nothing
    matched — not a fallback, and not a judgement that the role should hold nothing.

    An UNKNOWN role raises. `load_dispositions` refuses a typo written in the table; it cannot
    see the role the projection is asked for, and those are different typos in different files.
    Returning the filter's honest empty answer for one is the deny-all-by-accident state this
    module exists to make unreachable: every verb then decides UNDECLARED with "this role holds
    no grant reaching it", which is #995's original symptom reached from a one-character slip at
    a call site. The membership set is in scope here; nothing is bought by not checking it.

    Do NOT read the empty return as the mechanism behind the adversarial judge's empty grant:
    that stage is handed `DENY_ALL` explicitly by `_run_judge_pydantic` and never reaches here.
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

    PURE, and takes `walked` as an argument rather than resolving it. Resolving the census
    reads the committed tree through git, and this module is imported while the runtime builds
    its agent definitions — where a git subprocess has no business running. The gate that
    supplies `walked` is a CI script, which is the right place for it.

    Both directions are reported. `undecided` is the reported defect: a verb the tree declares
    and the table ignores, which today means silently ungranted. `phantom` is its mirror: a row
    for a verb no adapter declares any more, which would otherwise surface much later as a
    startup failure when the registry cross-checks the grant.

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
